# main.py
import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, send_file
from supabase import create_client, Client
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from io import BytesIO

# --- Config ---
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
SECRET_KEY = os.environ.get("SECRET_KEY", "verander_dit_naar_een_random_string")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("SUPABASE_URL en SUPABASE_KEY moeten als environment variables gezet zijn.")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

APP_NAME = "LP Group Drive"
MAX_BYTES_PER_USER = 100 * 1024 * 1024  # 100 MB per gebruiker

app = Flask(__name__)
app.secret_key = SECRET_KEY

# --- Helpers voor Supabase / gebruikers --- #

def get_user_by_username(username):
    res = supabase.table("users").select("*").eq("username", username).limit(1).execute()
    return res.data[0] if res.data else None

def create_user(username, password, is_admin=False, is_staff=False):
    pw_hash = generate_password_hash(password)
    payload = {
        "username": username,
        "password_hash": pw_hash,
        "active": True,
        "is_admin": is_admin,
        "is_staff": is_staff
    }
    return supabase.table("users").insert(payload).execute()

def update_password(user_id, new_password):
    pw_hash = generate_password_hash(new_password)
    return supabase.table("users").update({"password_hash": pw_hash}).eq("id", user_id).execute()

def set_user_active(user_id, active_bool):
    return supabase.table("users").update({"active": bool(active_bool)}).eq("id", user_id).execute()

def set_user_staff(user_id, is_staff_bool):
    return supabase.table("users").update({"is_staff": bool(is_staff_bool)}).eq("id", user_id).execute()

def list_users(include_admins=True):
    q = supabase.table("users").select("*")
    if not include_admins:
        q = q.eq("is_admin", False)
    return q.order("username", {"ascending": True}).execute().data

# Storage helpers (bucket 'uploads' moet bestaan in Supabase)
BUCKET_NAME = "uploads"

def upload_user_file(username, filename, file_bytes):
    path = f"{username}/{filename}"
    # delete if exists first
    try:
        supabase.storage.from_(BUCKET_NAME).remove([path])
    except Exception:
        pass
    res = supabase.storage.from_(BUCKET_NAME).upload(path, file_bytes)
    return res

def download_user_file(username, filename):
    path = f"{username}/{filename}"
    # we can get public URL if bucket public; here we'll generate signed URL
    res = supabase.storage.from_(BUCKET_NAME).download(path)
    return res  # bytes

def delete_user_file(username, filename):
    path = f"{username}/{filename}"
    return supabase.storage.from_(BUCKET_NAME).remove([path])

def get_user_files_list(username):
    # list files under prefix username/
    res = supabase.storage.from_(BUCKET_NAME).list(prefix=f"{username}/")
    # res is list of objects with 'name' etc.
    files = []
    for item in (res or []):
        # supabase returns names like 'username/file.ext' or just 'file.ext' depending; normalize
        name = item.get("name") or item.get("id") or item
        if name.startswith(f"{username}/"):
            name = name.split('/', 1)[1]
        files.append({
            "name": name,
            "size": item.get("size", 0)
        })
    return sorted(files, key=lambda x: x['name'].lower())

def get_user_total_bytes(username):
    files = get_user_files_list(username)
    return sum(f['size'] for f in files)

# --- Ensure admin exists (run once) --- #
def ensure_admin():
    admin = get_user_by_username("admin")
    if not admin:
        create_user("admin", "adminLP", is_admin=True, is_staff=False)

# --- Routes --- #
@app.context_processor
def inject_globals():
    return {"app_name": APP_NAME, "username": session.get("username"), "is_admin": session.get("is_admin", False), "is_staff": session.get("is_staff", False)}

@app.route("/")
def index():
    if "username" in session:
        if session.get("is_admin"):
            return redirect(url_for("admin_panel"))
        if session.get("is_staff"):
            return redirect(url_for("staff_panel"))
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

# LOGIN / LOGOUT
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Vul alle velden in", "danger"); return redirect(url_for("login"))
        user = get_user_by_username(username)
        if user and user.get("active") and check_password_hash(user.get("password_hash",""), password):
            session["username"] = username
            session["user_id"] = user["id"]
            session["is_admin"] = bool(user.get("is_admin"))
            session["is_staff"] = bool(user.get("is_staff"))
            flash("Succesvol ingelogd", "success")
            if user.get("is_admin"):
                return redirect(url_for("admin_panel"))
            if user.get("is_staff"):
                return redirect(url_for("staff_panel"))
            return redirect(url_for("dashboard"))
        else:
            flash("Ongeldige inloggegevens", "danger")
            return redirect(url_for("login"))
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Je bent uitgelogd", "info")
    return redirect(url_for("login"))

# DASHBOARD (gebruiker)
@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        flash("Log eerst in", "danger"); return redirect(url_for("login"))
    if session.get("is_admin") or session.get("is_staff"):
        # staff/admin hebben geen dashboard uploads
        flash("Geen toegang tot gebruikersdashboard", "danger")
        return redirect(url_for("index"))
    username = session["username"]
    files = get_user_files_list(username)
    used = get_user_total_bytes(username)
    return render_template("dashboard.html", files=files, used=used, limit=MAX_BYTES_PER_USER)

@app.route("/upload", methods=["POST"])
def upload():
    if "username" not in session:
        flash("Log eerst in", "danger"); return redirect(url_for("login"))
    if session.get("is_admin") or session.get("is_staff"):
        flash("Geen uploadrechten", "danger"); return redirect(url_for("index"))
    username = session["username"]
    if "file" not in request.files:
        flash("Geen bestand geselecteerd", "danger"); return redirect(url_for("dashboard"))
    f = request.files["file"]
    if f.filename == "":
        flash("Geen bestand geselecteerd", "danger"); return redirect(url_for("dashboard"))
    safe = secure_filename(f.filename)
    if not safe:
        flash("Ongeldige bestandsnaam", "danger"); return redirect(url_for("dashboard"))
    # size check
    data = f.read()
    size = len(data)
    used = get_user_total_bytes(username)
    if used + size > MAX_BYTES_PER_USER:
        flash("Onvoldoende ruimte. Verwijder eerst bestanden.", "danger"); return redirect(url_for("dashboard"))
    # upload to supabase
    upload_user_file(username, safe, data)
    flash(f'Bestand "{safe}" geüpload', "success")
    return redirect(url_for("dashboard"))

@app.route("/download/<filename>")
def download(filename):
    if "username" not in session:
        flash("Log eerst in", "danger"); return redirect(url_for("login"))
    username = session["username"]
    if session.get("is_admin") or session.get("is_staff"):
        flash("Geen downloadrechten", "danger"); return redirect(url_for("index"))
    safe = secure_filename(filename)
    try:
        data = download_user_file(username, safe)  # returns bytes
    except Exception:
        abort(404)
    if not data:
        abort(404)
    # serve as attachment
    return send_file(BytesIO(data), download_name=safe, as_attachment=True)

@app.route("/delete/<filename>", methods=["POST"])
def delete_file(filename):
    if "username" not in session:
        flash("Log eerst in", "danger"); return redirect(url_for("login"))
    username = session["username"]
    if session.get("is_admin") or session.get("is_staff"):
        flash("Geen delete rechten", "danger"); return redirect(url_for("index"))
    safe = secure_filename(filename)
    try:
        delete_user_file(username, safe)
        flash(f'Bestand "{safe}" verwijderd', "success")
    except Exception:
        flash("Kon bestand niet verwijderen", "danger")
    return redirect(url_for("dashboard"))

# ADMIN routes
@app.route("/admin")
def admin_panel():
    if "username" not in session:
        flash("Log eerst in", "danger"); return redirect(url_for("login"))
    if not session.get("is_admin"):
        flash("Geen toegang", "danger"); return redirect(url_for("index"))
    users = list_users()
    return render_template("admin.html", users=users)

@app.route("/admin/create_user", methods=["POST"])
def admin_create_user():
    if "username" not in session or not session.get("is_admin"):
        flash("Geen toegang", "danger"); return redirect(url_for("login"))
    new_username = request.form.get("new_username","").strip()
    new_password = request.form.get("new_password","")
    role = request.form.get("user_role","user")
    if not new_username or not new_password:
        flash("Vul alle velden in", "danger"); return redirect(url_for("admin_panel"))
    if get_user_by_username(new_username):
        flash("Gebruikersnaam bestaat al", "danger"); return redirect(url_for("admin_panel"))
    is_staff_flag = True if role == "staff" else False
    create_user(new_username, new_password, is_admin=(role=="admin"), is_staff=is_staff_flag)
    flash(f'Gebruiker "{new_username}" aangemaakt', "success")
    return redirect(url_for("admin_panel"))

@app.route("/admin/toggle_user/<int:user_id>", methods=["POST"])
def admin_toggle_user(user_id):
    if "username" not in session or not session.get("is_admin"):
        flash("Geen toegang", "danger"); return redirect(url_for("login"))
    user = supabase.table("users").select("*").eq("id", user_id).limit(1).execute().data
    if not user:
        flash("Gebruiker niet gevonden", "danger"); return redirect(url_for("admin_panel"))
    user = user[0]
    if user.get("is_admin"):
        flash("Je kan admin niet deactiveren", "danger"); return redirect(url_for("admin_panel"))
    set_user_active(user_id, not user.get("active"))
    flash("Status gewijzigd", "success")
    return redirect(url_for("admin_panel"))

@app.route("/admin/reset_password/<int:user_id>", methods=["GET","POST"])
def admin_reset_password(user_id):
    if "username" not in session or not session.get("is_admin"):
        flash("Geen toegang", "danger"); return redirect(url_for("login"))
    if request.method == "POST":
        new_password = request.form.get("new_password","")
        if not new_password or len(new_password) < 4:
            flash("Wachtwoord te kort", "danger"); return redirect(url_for("admin_reset_password", user_id=user_id))
        update_password(user_id, new_password)
        flash("Wachtwoord gewijzigd", "success")
        return redirect(url_for("admin_panel"))
    # GET: show form
    user = supabase.table("users").select("*").eq("id", user_id).limit(1).execute().data
    if not user:
        flash("Gebruiker niet gevonden", "danger"); return redirect(url_for("admin_panel"))
    return render_template("reset_password.html", target_user=user[0], back_url=url_for("admin_panel"))

@app.route("/admin/set_role/<int:user_id>", methods=["POST"])
def admin_set_role(user_id):
    if "username" not in session or not session.get("is_admin"):
        flash("Geen toegang", "danger"); return redirect(url_for("login"))
    new_role = request.form.get("new_role","user")
    if new_role == "staff":
        set_user_staff(user_id, True)
    else:
        set_user_staff(user_id, False)
    flash("Rol aangepast", "success")
    return redirect(url_for("admin_panel"))

# STAFF routes
@app.route("/staff")
def staff_panel():
    if "username" not in session:
        flash("Log eerst in", "danger"); return redirect(url_for("login"))
    if not session.get("is_staff") and not session.get("is_admin"):
        flash("Geen toegang", "danger"); return redirect(url_for("index"))
    # staff sees only regular users (no admin)
    users = list_users(include_admins=False)
    return render_template("staff.html", users=users)

@app.route("/staff/create_user", methods=["POST"])
def staff_create_user():
    if "username" not in session or not session.get("is_staff"):
        flash("Geen toegang", "danger"); return redirect(url_for("login"))
    new_username = request.form.get("new_username","").strip()
    new_password = request.form.get("new_password","")
    if not new_username or not new_password:
        flash("Vul alle velden in", "danger"); return redirect(url_for("staff_panel"))
    if get_user_by_username(new_username):
        flash("Gebruikersnaam bestaat al", "danger"); return redirect(url_for("staff_panel"))
    create_user(new_username, new_password, is_admin=False, is_staff=False)
    flash(f'Gebruiker "{new_username}" aangemaakt', "success")
    return redirect(url_for("staff_panel"))

@app.route("/staff/reset_password/<int:user_id>", methods=["GET","POST"])
def staff_reset_password(user_id):
    if "username" not in session or not (session.get("is_staff") or session.get("is_admin")):
        flash("Geen toegang", "danger"); return redirect(url_for("login"))
    # staff mag geen admin of staff resetten
    user = supabase.table("users").select("*").eq("id", user_id).limit(1).execute().data
    if not user:
        flash("Gebruiker niet gevonden", "danger"); return redirect(url_for("staff_panel"))
    user = user[0]
    if user.get("is_admin") or user.get("is_staff"):
        flash("Geen permissie om deze gebruiker te wijzigen", "danger"); return redirect(url_for("staff_panel"))
    if request.method == "POST":
        new_password = request.form.get("new_password","")
        if not new_password or len(new_password) < 4:
            flash("Wachtwoord te kort", "danger"); return redirect(url_for("staff_reset_password", user_id=user_id))
        update_password(user_id, new_password)
        flash("Wachtwoord gewijzigd", "success")
        return redirect(url_for("staff_panel"))
    return render_template("reset_password.html", target_user=user, back_url=url_for("staff_panel"))

# --- Startup ---
if __name__ == "__main__":
    ensure_admin()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
