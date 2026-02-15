import os
import re
import bcrypt
import certifi
from flask import Flask, render_template, request, redirect, session
from pymongo import MongoClient
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)

# -------------------------
# Secure Configuration
# -------------------------
secret_key = os.getenv("SECRET_KEY")
if not secret_key:
    raise RuntimeError("SECRET_KEY not set in .env")

app.secret_key = secret_key

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,   # Set True in production with HTTPS
    SESSION_COOKIE_SAMESITE="Lax"
)

# -------------------------
# MongoDB Atlas Connection
# -------------------------
mongo_uri = os.getenv("MONGO_URI")
if not mongo_uri:
    raise RuntimeError("MONGO_URI not set in .env")

try:
    client = MongoClient(
        mongo_uri,
        tls=True,
        tlsCAFile=certifi.where(),
        serverSelectionTimeoutMS=5000
    )

    # Force connection check
    client.admin.command("ping")

except Exception as e:
    raise RuntimeError(f"Database connection failed: {e}")

db = client["secure_auth"]
users = db["users"]

# -------------------------
# Helper: Strong Password
# -------------------------
def is_strong_password(password):
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    return True

# -------------------------
# Routes
# -------------------------

@app.route("/")
def home():
    return redirect("/login")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            return "Invalid input", 400

        if not is_strong_password(password):
            return "Password must be 8+ chars, include uppercase, lowercase and number.", 400

        if users.find_one({"username": username}):
            return "User already exists.", 400

        hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

        users.insert_one({
            "username": username,
            "password": hashed_pw
        })

        return redirect("/login")

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = users.find_one({"username": username})

        if user and bcrypt.checkpw(password.encode(), user["password"]):
            session.clear()
            session["user"] = username
            return redirect("/dashboard")

        return "Invalid credentials", 401

    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/login")

    return render_template("dashboard.html", user=session["user"])

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.errorhandler(404)
def not_found(e):
    return "Page not found", 404

# -------------------------
# Run Application
# -------------------------
if __name__ == "__main__":
    app.run()