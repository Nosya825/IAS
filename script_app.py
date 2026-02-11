# -----------------------------
# Imports & Setup
# -----------------------------
# Flask core tools + authentication libraries
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

# Initialize Flask app and security tools
app = Flask(__name__)
app.secret_key = "supersecretkey"  # Used to protect session data
bcrypt = Bcrypt(app)               # Handles password hashing
login_manager = LoginManager(app)  # Manages login sessions
login_manager.login_view = "login" # Redirect unauthenticated users to login


# -----------------------------
# Temporary User Storage
# -----------------------------
# Simulated database (in-memory dictionary)
# Stores hashed passwords and user roles
users = {
    "admin": {"password": bcrypt.generate_password_hash("Admin123").decode("utf-8"), "role": "Admin"},
    "user": {"password": bcrypt.generate_password_hash("User123").decode("utf-8"), "role": "User"}
}


# -----------------------------
# User Class for Flask-Login
# -----------------------------
# Represents a logged-in user session
class User(UserMixin):
    def __init__(self, username, role):
        self.id = username
        self.role = role


# Flask-Login loader: recreates user from session
@login_manager.user_loader
def load_user(username):
    if username in users:
        return User(username, users[username]["role"])
    return None


# -----------------------------
# Routes
# -----------------------------

# Redirect homepage → login page
@app.route("/")
def home():
    return redirect(url_for("login"))


# User Registration
# GET: show form | POST: create account
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = bcrypt.generate_password_hash(request.form["password"]).decode("utf-8")
        role = request.form.get("role", "User")

        users[username] = {"password": password, "role": role}
        return redirect(url_for("login"))

    return render_template("register.html")


# Login System
# Validates credentials and creates session
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if username in users and bcrypt.check_password_hash(users[username]["password"], password):
            user = User(username, users[username]["role"])
            login_user(user)
            session["role"] = user.role
            return redirect(url_for("dashboard"))
        else:
            flash("❌ Invalid username or password")
            return render_template("login.html", username=username)

    return render_template("login.html")


# Dashboard (protected page)
# Shows content based on role
@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.role == "Admin":
        return render_template("dashboard.html", message="Welcome Admin!", role=current_user.role)
    return render_template("dashboard.html", message="Welcome User!", role=current_user.role)


# Admin-only route
# Blocks access if role is not Admin
@app.route("/admin")
@login_required
def admin():
    if session.get("role") != "Admin":
        return "Access Denied", 403
    return render_template("admin.html")


# Logout and clear session
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


# -----------------------------
# Run Server
# -----------------------------
# Debug mode auto-reloads on changes
if __name__ == "__main__":
    app.run(debug=True)
