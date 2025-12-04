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
    storage_list = [{"name": f["name"], "size": f.get("
