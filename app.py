import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, Response
from supabase import create_client
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "gebruik_een_veilige_sleutel")

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

BUCKET_NAME = "userfiles"
MAX_USER_STORAGE = 100 * 1024 * 1024  # 100 MB

# ---------------- HELPERS --------------------
def is_logged():
    return "username" in session

def is_admin():
    return session.get("is_admin", False)

def is_staff():
    return session.get("is_staff", False)

def storage_used(user_id):
    files = supabase.storage.from_(BUCKET_NAME).list(path=str(user_id))
    return sum(f.get("metadata", {}).get("size", 0) for f in files)

def get_user(user_id):
    res = supabase.table("users").select("*").eq("id", user_id).single().execute()
    return res.data

def get_user_by_username(username):
    res = supabase.table("users").select("*").eq("username", username).single().execute()
    return res.data

# ---------------- LOGIN --------------------
@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = get_user_by_username(username)
        if user and user.get("active", True) and check_password_hash(user["password_hash"], password):
            session["username"] = user["username"]
            session["user_id"] = user["id"]
            session["is_admin"] = bool(user.get("is_admin", False))
            session["is_staff"] = bool(user.get("is_staff", False))

            flash("Succesvol ingelogd", "success")

            if is_admin():
                return redirect(url_for("admin_panel"))
            elif is_staff():
                return redirect(url_for("staff_panel"))
            else:
                return redirect(url_for("dashboard"))

        flash("Foute gegevens of account niet actief", "danger")
        return redirect(url_for("login"))

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------------- DASHBOARD --------------------
@app.route("/dashboard")
def dashboard():
    if not is_logged():
        return redirect(url_for("login"))

    user_id = session["user_id"]

    # Bestanden uit storage
    storage_files = supabase.storage.from_(BUCKET_NAME).list(path=str(user_id))
    storage_list = [{"name": f["name"], "size": f.get("metadata", {}).get("size", 0)} for f in storage_files]

    # Metadata uit tabel
    res = supabase.table("files").select("*").eq("user_id", user_id).execute()
    db_files = res.data or []

    return render_template("dashboard.html",
                           files=storage_list,
                           db_files=db_files,
                           used=sum(f["size"] for f in storage_list),
                           limit=MAX_USER_STORAGE)

# ---------------- UPLOAD / DELETE / DOWNLOAD --------------------
@app.route("/upload", methods=["POST"])
def upload():
    if not is_logged():
        return redirect(url_for("login"))

    user_id = session["user_id"]
    file = request.files.get("file")
    if not file:
        flash("Geen bestand gekozen", "danger")
        return redirect(url_for("dashboard"))

    filename = secure_filename(file.filename)
    file.seek(0, 2)
    file_size = file.tell()
    file.seek(0)

    if storage_used(user_id) + file_size > MAX_USER_STORAGE:
        flash("Niet genoeg opslagruimte", "danger")
        return redirect(url_for("dashboard"))

    # Upload als bytes
    supabase.storage.from_(BUCKET_NAME).upload(f"{user_id}/{filename}", file.read())

    # Metadata opslaan
    supabase.table("files").insert([{
        "user_id": user_id,
        "filename": filename,
        "size": file_size,
        "created_at": datetime.utcnow().isoformat()
    }]).execute()

    flash("Bestand geüpload", "success")
    return redirect(url_for("dashboard"))

@app.route("/delete/<filename>", methods=["POST"])
def delete_file(filename):
    if not is_logged():
        return redirect(url_for("login"))

    user_id = session["user_id"]
    safe_name = secure_filename(filename)

    supabase.storage.from_(BUCKET_NAME).remove([f"{user_id}/{safe_name}"])
    supabase.table("files").delete().eq("user_id", user_id).eq("filename", safe_name).execute()

    flash("Bestand verwijderd", "success")
    return redirect(url_for("dashboard"))

@app.route("/download/<filename>")
def download(filename):
    if not is_logged():
        return redirect(url_for("login"))

    user_id = session["user_id"]
    safe_name = secure_filename(filename)
    data = supabase.storage.from_(BUCKET_NAME).download(f"{user_id}/{safe_name}")

    if data:
        return Response(
            data,
            mimetype="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename={safe_name}"}
        )
    else:
        flash("Download mislukt", "danger")
        return redirect(url_for("dashboard"))

# ---------------- STAFF --------------------
@app.route("/staff")
def staff_panel():
    if not (is_staff() or is_admin()):
        return render_template("not_allowed.html")

    res = supabase.table("users").select("*").neq("is_admin", True).execute()
    users = res.data or []
    return render_template("staff_panel.html", users=users)

@app.route("/staff/create", methods=["POST"])
def staff_create_user():
    if not (is_staff() or is_admin()):
        return render_template("not_allowed.html")

    username = request.form["new_username"]
    password = request.form["new_password"]

    try:
        supabase.table("users").insert([{
            "username": username,
            "password_hash": generate_password_hash(password),
            "is_staff": False,  # staff mag enkel gewone gebruikers maken
            "active": True
        }]).execute()
        flash("Gebruiker aangemaakt", "success")
    except Exception as e:
        flash(f"Fout bij aanmaken gebruiker: {e}", "danger")

    return redirect(url_for("staff_panel"))

# ---------------- ADMIN --------------------
@app.route("/admin")
def admin_panel():
    if not is_admin():
        return render_template("not_allowed.html")
    return render_template("admin_panel.html")

@app.route("/admin/users")
def admin_users():
    if not is_admin():
        return render_template("not_allowed.html")
    res = supabase.table("users").select("*").execute()
    users = res.data or []
    return render_template("admin_users.html", users=users)

@app.route("/admin/create", methods=["POST"])
def admin_create_user():
    if not is_admin():
        return render_template("not_allowed.html")

    username = request.form["new_username"]
    password = request.form["new_password"]
    role = request.form["role"]
    is_staff_value = role == "staff"

    try:
        supabase.table("users").insert([{
            "username": username,
            "password_hash": generate_password_hash(password),
            "is_staff": is_staff_value,
            "active": True
        }]).execute()
        flash("Gebruiker/staff aangemaakt", "success")
    except Exception as e:
        flash(f"Fout bij aanmaken gebruiker: {e}", "danger")

    return redirect(url_for("admin_users"))

@app.route("/admin/reset/<int:user_id>", methods=["GET", "POST"])
def admin_reset_password(user_id):
    if not (is_admin() or is_staff()):
        return render_template("not_allowed.html")

    if request.method == "POST":
        password = request.form["new_password"]
        supabase.table("users").update({
            "password_hash": generate_password_hash(password)
        }).eq("id", user_id).execute()
        flash("Wachtwoord veranderd", "success")
        return redirect(url_for("admin_users"))

    return render_template("reset_password.html")

@app.route("/admin/toggle/<int:user_id>", methods=["POST"])
def admin_toggle_user(user_id):
    if not is_admin():
        return render_template("not_allowed.html")

    user = get_user(user_id)
    if not user:
        flash("Gebruiker niet gevonden", "danger")
        return redirect(url_for("admin_users"))

    new_state = not user.get("active", True)
    supabase.table("users").update({"active": new_state}).eq("id", user_id).execute()
    flash("Gebruikerstatus aangepast", "success")
    return redirect(url_for("admin_users"))
