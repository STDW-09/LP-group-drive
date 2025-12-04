import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from supabase import create_client
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# --- Flask setup ---
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "gebruik_een_veilige_sleutel")

# --- Supabase client ---
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

def storage_used(username):
    try:
        files = supabase.storage.from_(BUCKET_NAME).list(path=username)
        return sum(f.get("metadata", {}).get("size", 0) for f in files)
    except Exception:
        return 0

def get_user(user_id):
    try:
        res = supabase.table("users").select("*").eq("id", user_id).single().execute()
        return res.data
    except Exception:
        return None

def get_user_by_username(username):
    try:
        res = supabase.table("users").select("*").eq("username", username).single().execute()
        return res.data
    except Exception:
        return None

# ---------------- LOGIN / LOGOUT --------------------
@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        name = request.form.get("username", "").strip()
        pw = request.form.get("password", "")

        user = get_user_by_username(name)
        if not user:
            flash("Gebruiker niet gevonden", "danger")
            return redirect(url_for("login"))

        if not user.get("active", True):
            flash("Gebruiker is geblokkeerd", "danger")
            return redirect(url_for("login"))

        if check_password_hash(user["password_hash"], pw):
            session["username"] = user["username"]
            session["user_id"] = user["id"]
            session["is_admin"] = bool(user.get("is_admin", False))
            session["is_staff"] = bool(user.get("is_staff", False))
            flash("Succesvol ingelogd", "success")

            if is_admin():
                return redirect(url_for("admin_panel"))
            if is_staff():
                return redirect(url_for("staff_panel"))
            return redirect(url_for("dashboard"))
        else:
            flash("Foute gegevens", "danger")
            return redirect(url_for("login"))

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------------- USER DASHBOARD --------------------
@app.route("/dashboard")
def dashboard():
    if not is_logged():
        return redirect(url_for("login"))

    if is_admin():
        return redirect(url_for("admin_panel"))
    if is_staff():
        return redirect(url_for("staff_panel"))

    username = session["username"]
    files = supabase.storage.from_(BUCKET_NAME).list(path=username)
    file_list = [{"name": f["name"], "size": f.get("metadata", {}).get("size", 0)} for f in files]

    return render_template("dashboard.html",
                           files=file_list,
                           used=sum(f["size"] for f in file_list),
                           limit=MAX_USER_STORAGE)

@app.route("/upload", methods=["POST"])
def upload():
    if not is_logged():
        return redirect(url_for("login"))

    username = session["username"]
    file = request.files.get("file")

    if not file:
        flash("Geen bestand gekozen", "danger")
        return redirect(url_for("dashboard"))

    filename = secure_filename(file.filename)

    # groottecheck
    file.seek(0, 2)
    file_size = file.tell()
    file.seek(0)
    if storage_used(username) + file_size > MAX_USER_STORAGE:
        flash("Niet genoeg opslagruimte", "danger")
        return redirect(url_for("dashboard"))

    try:
        supabase.storage.from_(BUCKET_NAME).upload(f"{username}/{filename}", file)
        flash("Bestand geüpload", "success")
    except Exception:
        flash("Upload mislukt", "danger")

    return redirect(url_for("dashboard"))

@app.route("/delete/<filename>", methods=["POST"])
def delete_file(filename):
    if not is_logged():
        return redirect(url_for("login"))

    username = session["username"]
    try:
        supabase.storage.from_(BUCKET_NAME).remove([f"{username}/{secure_filename(filename)}"])
        flash("Bestand verwijderd", "success")
    except Exception:
        flash("Verwijderen mislukt", "danger")

    return redirect(url_for("dashboard"))

@app.route("/download/<filename>")
def download(filename):
    if not is_logged():
        return redirect(url_for("login"))

    username = session["username"]
    try:
        file_data = supabase.storage.from_(BUCKET_NAME).download(f"{username}/{secure_filename(filename)}")
        return (file_data, 200, {
            "Content-Type": "application/octet-stream",
            "Content-Disposition": f"attachment; filename={filename}"
        })
    except Exception:
        flash("Download mislukt", "danger")
        return redirect(url_for("dashboard"))

# ---------------- STAFF --------------------
@app.route("/staff")
def staff_panel():
    if not is_staff() and not is_admin():
        return render_template("not_allowed.html")

    res = supabase.table("users").select("*").neq("is_admin", True).execute()
    users = res.data
    return render_template("staff_panel.html", users=users)

@app.route("/staff/create", methods=["POST"])
def staff_create_user():
    if not is_staff() and not is_admin():
        return render_template("not_allowed.html")

    username = request.form["new_username"]
    pw = request.form["new_password"]

    try:
        supabase.table("users").insert([{
            "username": username,
            "password_hash": generate_password_hash(pw),
            "is_staff": True
        }]).execute()
        flash("Gebruiker aangemaakt", "success")
    except Exception:
        flash("Gebruiker bestaat mogelijk al", "danger")

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
    users = res.data
    return render_template("admin_users.html", users=users)

@app.route("/admin/create", methods=["POST"])
def admin_create_user():
    if not is_admin():
        return render_template("not_allowed.html")

    name = request.form["new_username"]
    pw = request.form["new_password"]
    role = request.form["role"]
    is_staff_value = True if role == "staff" else False

    try:
        supabase.table("users").insert([{
            "username": name,
            "password_hash": generate_password_hash(pw),
            "is_staff": is_staff_value
        }]).execute()
        flash("Gebruiker/staff aangemaakt", "success")
    except Exception:
        flash("Gebruiker bestaat mogelijk al", "danger")

    return redirect(url_for("admin_users"))

@app.route("/admin/reset/<int:user_id>", methods=["GET", "POST"])
def admin_reset_password(user_id):
    if not is_admin() and not is_staff():
        return render_template("not_allowed.html")

    if request.method == "POST":
        pw = request.form["new_password"]
        try:
            supabase.table("users").update({
                "password_hash": generate_password_hash(pw)
            }).eq("id", user_id).execute()
            flash("Wachtwoord veranderd", "success")
        except Exception:
            flash("Wachtwoord kon niet veranderd worden", "danger")
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
    try:
        supabase.table("users").update({"active": new_state}).eq("id", user_id).execute()
        flash("Status aangepast", "success")
    except Exception:
        flash("Kon status niet aanpassen", "danger")

    return redirect(url_for("admin_users"))

# ------------------- RUN -------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
