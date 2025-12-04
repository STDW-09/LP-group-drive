import os
import sqlite3
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
DB_PATH = "users.db"
MAX_USER_STORAGE = 100 * 1024 * 1024   # 100 MB


# ---------------- DATABASE --------------------

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            is_staff INTEGER DEFAULT 0,
            active INTEGER DEFAULT 1
        )
    """)

    # admin toevoegen indien niet aanwezig
    c.execute("SELECT * FROM users WHERE username = 'admin'")
    if not c.fetchone():
        admin_pw = os.environ.get("ADMIN_PASSWORD", "admin")
        c.execute(
            "INSERT INTO users (username, password_hash, is_admin, is_staff, active) 
             VALUES (?, ?, 1, 0, 1)",
            ("admin", generate_password_hash(admin_pw))
        )

    conn.commit()
    conn.close()

init_db()


# ---------------- HELPERS --------------------

def is_logged():
    return "username" in session

def is_admin():
    return session.get("is_admin", False)

def is_staff():
    return session.get("is_staff", False)

def storage_used(username):
    files = supabase.storage.from_(BUCKET_NAME).list(path=username)
    return sum(f.get("metadata", {}).get("size", 0) for f in files)


# ---------------- LOGIN / LOGOUT --------------------

@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        name = request.form.get("username").strip()
        pw = request.form.get("password")

        conn = db()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=? AND active=1", (name,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], pw):
            session["username"] = user["username"]
            session["user_id"] = user["id"]
            session["is_admin"] = bool(user["is_admin"])
            session["is_staff"] = bool(user["is_staff"])

            flash("Succesvol ingelogd", "success")

            if is_admin():
                return redirect(url_for("admin_panel"))
            if is_staff():
                return redirect(url_for("staff_panel"))
            return redirect(url_for("dashboard"))

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

    res = supabase.storage.from_(BUCKET_NAME).upload(f"{username}/{filename}", file)
    if res:
        flash("Bestand geüpload naar Supabase", "success")
    else:
        flash("Upload mislukt", "danger")

    return redirect(url_for("dashboard"))


@app.route("/delete/<filename>", methods=["POST"])
def delete_file(filename):
    if not is_logged():
        return redirect(url_for("login"))

    username = session["username"]
    supabase.storage.from_(BUCKET_NAME).remove([f"{username}/{secure_filename(filename)}"])
    flash("Bestand verwijderd", "success")

    return redirect(url_for("dashboard"))


@app.route("/download/<filename>")
def download(filename):
    if not is_logged():
        return redirect(url_for("login"))

    username = session["username"]
    res = supabase.storage.from_(BUCKET_NAME).download(f"{username}/{secure_filename(filename)}")

    if not res:
        flash("Download mislukt", "danger")
        return redirect(url_for("dashboard"))

    return (
        res,
        200,
        {
            "Content-Type": "application/octet-stream",
            "Content-Disposition": f"attachment; filename={filename}",
        },
    )


# ---------------- STAFF --------------------

@app.route("/staff")
def staff_panel():
    if not is_staff() and not is_admin():
        return render_template("not_allowed.html")

    conn = db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE is_admin=0")
    users = c.fetchall()
    conn.close()

    return render_template("staff_panel.html", users=users)


@app.route("/staff/create", methods=["POST"])
def staff_create_user():
    if not is_staff() and not is_admin():
        return render_template("not_allowed.html")

    username = request.form["new_username"]
    pw = request.form["new_password"]

    conn = db()
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                  (username, generate_password_hash(pw)))
        conn.commit()
        flash("Gebruiker aangemaakt", "success")
    except sqlite3.IntegrityError:
        flash("Gebruiker bestaat al", "danger")
    finally:
        conn.close()

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

    conn = db()
    c = conn.cursor()
    c.execute("SELECT * FROM users")
    users = c.fetchall()
    conn.close()

    return render_template("admin_users.html", users=users)


@app.route("/admin/create", methods=["POST"])
def admin_create_user():
    if not is_admin():
        return render_template("not_allowed.html")

    name = request.form["new_username"]
    pw = request.form["new_password"]
    role = request.form["role"]

    is_staff_value = 1 if role == "staff" else 0

    conn = db()
    c = conn.cursor()
    try:
        c.execute(
            "INSERT INTO users (username, password_hash, is_staff) VALUES (?, ?, ?)",
            (name, generate_password_hash(pw), is_staff_value)
        )
        conn.commit()
        flash("Gebruiker/staff aangemaakt", "success")
    except sqlite3.IntegrityError:
        flash("Gebruiker bestaat al", "danger")
    finally:
        conn.close()

    return redirect(url_for("admin_users"))


@app.route("/admin/reset/<int:user_id>", methods=["GET", "POST"])
def admin_reset_password(user_id):
    if not is_admin() and not is_staff():
        return render_template("not_allowed.html")

    if request.method == "POST":
        pw = request.form["new_password"]
        conn = db()
        c = conn.cursor()
        c.execute("UPDATE users SET password_hash=? WHERE id=?",
                  (generate_password_hash(pw), user_id))
        conn.commit()
        conn.close()
        flash("Wachtwoord veranderd", "success")
        return redirect(url_for("admin_users"))

    return render_template("reset_password.html")


@app.route("/admin/toggle/<int:user_id>", methods=["POST"])
def admin_toggle_user(user_id):
    if not is_admin():
        return render_template("not_allowed.html")

    conn = db()
    c = conn.cursor()
    c.execute("SELECT active FROM users WHERE id=?", (user_id,))
    current = c.fetchone()["active"]

    new_state = 0 if current else 1

    c.execute("UPDATE users SET active=? WHERE id=?", (new_state, user_id))
    conn.commit()
    conn.close()

    return redirect(url_for("admin_users"))
