# app.py
"""
Secure GRC Portal - Flask App
This file demonstrates Secure Software Development requirements:
- Secure environment (use VS Code extensions SonarLint, GitGuardian, etc.)
- Input validation, output encoding, error handling
- Password hashing & authentication
- Security logging & safe defaults
"""

import os
import re
import sqlite3 
import json
import logging
from datetime import timedelta
from pathlib import Path
from functools import wraps

from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename as werkzeug_secure

from db import get_engine, get_session, close_session
from models import Base, User, Upload, ScanResult, Risk, Compliance, Dependency
from llm_scan import scan_file_for_grc

# ------------------------------------------------------------------------------
# Secure Development Environment Notes
# - Ensure VS Code has SonarLint, GitGuardian, Python Security Linter enabled
# - Use a .gitignore to avoid committing secrets/uploads/__pycache__
# - Run Bandit/Safety for static analysis
# ------------------------------------------------------------------------------

load_dotenv()

# Configure logging (no sensitive info)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)


def create_app():
    app = Flask(__name__, instance_relative_config=True)
 
 
    # Secure config
    app.config.update(
        SECRET_KEY=os.getenv("FLASK_SECRET", os.urandom(24)),
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=not app.debug,  # true in prod
        SESSION_COOKIE_SAMESITE="Lax",
        MAX_CONTENT_LENGTH=10*1024*1024  # 10 MB upload cap
    )

    # Ensure instance and uploads folders exist
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    Path("uploads").mkdir(exist_ok=True)

    # DB init
    engine = get_engine()
    Base.metadata.create_all(engine)

    # Seed admin user if none exists
    with engine.begin() as conn:
        if conn.exec_driver_sql("SELECT COUNT(*) FROM users").scalar() == 0:
            pw = generate_password_hash("Sksf1234")  # hashed
            conn.exec_driver_sql(
                "INSERT INTO users (email, password_hash, is_verified) VALUES (:e, :p, :v)",
                {"e": "kush786srj@gmail.com", "p": pw, "v": True},
            )
            logging.info("Default admin user created")

    # teardown hook for DB session
    @app.teardown_appcontext
    def teardown_db(exception=None):
        
        close_session()

    # ---------------------------
    # Helpers
    # ---------------------------
    def current_user():
        uid = session.get("user_id")
        if not uid:
            return None
        db = get_session()
        return db.get(User, uid)

    def login_required(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not current_user():
                flash("Please login first.", "warning")
                return redirect(url_for("login"))
            return f(*args, **kwargs)
        return wrapper

    # ---------------------------
    # Routes
    # ---------------------------

    @app.route("/", methods=["GET", "POST"])
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            # Input validation for email
            email = request.form.get("email", "").strip().lower()
            if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
                flash("Invalid email format.", "danger")
                return render_template("login.html")

            password = request.form.get("password", "")
            if not password or len(password) < 8:
                flash("Password must be at least 8 characters.", "danger")
                return render_template("login.html")

            db = get_session()
            user = db.query(User).filter(User.email == email).first()

            if user and check_password_hash(user.password_hash, password):
                if not user.is_verified:
                    flash("Your account exists but is NOT verified. Contact admin.", "warning")
                    return render_template("login.html")

                session["user_id"] = user.id
                session.permanent = True
                return redirect(url_for("home"))
            else:
                flash("Invalid credentials.", "danger")

        return render_template("login.html")

    @app.route("/logout")
    def logout():
        session.clear()
        flash("Logged out securely.", "info")
        return redirect(url_for("login"))

    @app.route("/home", methods=["GET", "POST"])
    @login_required
    def home():
        user = current_user()
        db = get_session()

        last_upload = (
            db.query(Upload)
            .filter(Upload.user_id == user.id)
            .order_by(Upload.uploaded_at.desc())
            .first()
        )

        upload_done = last_upload is not None
        scan_done = last_upload.scan_result is not None if last_upload else False
        has_scan = scan_done
        scan_result = last_upload.scan_result if scan_done else None

        # File upload (with validation)
        if request.method == "POST" and "file" in request.files:
            file = request.files["file"]
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                save_path = os.path.join("uploads", filename)

                # Avoid overwriting files
                base, ext = os.path.splitext(filename)
                i = 1
                while os.path.exists(save_path):
                    filename = f"{base}_{i}{ext}"
                    save_path = os.path.join("uploads", filename)
                    i += 1

                file.save(save_path)

                new_up = Upload(user_id=user.id, filename=filename, saved_path=save_path)
                db.add(new_up)
                db.commit()
                flash("File uploaded securely.", "success")
                return redirect(url_for("home"))
            else:
                flash("Invalid file type. Allowed: .pdf, .txt", "danger")

        return render_template(
            "home.html",
            user=user,
            upload_done=upload_done,
            scan_done=scan_done,
            has_scan=has_scan,
            last_upload=last_upload,
            scan_result=scan_result,
        )

    # ------------------------
    # Register Route
    # ------------------------
    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            email = request.form.get("email", "").strip()
            password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")

            # Validate email
            email_pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
            if not re.match(email_pattern, email):
                error = "Invalid email format!"
                return render_template("register.html", error=error)

            # Validate password length and complexity
            if len(password) < 8 or not re.search(r'[A-Za-z]', password) or not re.search(r'\d', password):
                error = "Password must be at least 8 characters long and contain at least one alphabet and one number."
                return render_template("register.html", error=error)

            # Confirm password check
            if password != confirm_password:
                error = "Passwords do not match!"
                return render_template("register.html", error=error)
        
            # Hash and save user
            hashed_pw = generate_password_hash(password)

            conn = sqlite3.connect("instance/app.db")
            cur = conn.cursor()
            try:
                cur.execute("INSERT INTO users (email, password_hash, is_verified) VALUES (?, ?, ?)",
                        (email, hashed_pw, 1))
                conn.commit()
            except sqlite3.IntegrityError:
                error = "User with this email already exists!"
                return render_template("register.html", error=error)
            finally:
                conn.close()

            flash("User registered successfully! Please login.")
            return redirect(url_for("login"))
        
        # GET request → just show form
        return render_template("register.html")
       




    @app.route("/scan/<int:upload_id>", methods=["POST"])
    @login_required
    def scan(upload_id):
        db = get_session()
        up = db.get(Upload, upload_id)

        if not up or up.user_id != session.get("user_id"):
            flash("Upload not found or unauthorized.", "danger")
            return redirect(url_for("home"))

        if up.scan_result:
            flash("This file has already been scanned.", "info")
            return redirect(url_for("home"))

        try:
            data = scan_file_for_grc(up.saved_path)
            res = ScanResult(
                upload_id=up.id,
                summary=data.get("summary", ""),
                compliance_hits_json=json_dumps(data.get("compliance_hits", [])),
                risks_json=json_dumps(data.get("risks", [])),
            )
            db.add(res)
            db.commit()
            flash("Scan completed and saved.", "success")
        except Exception as e:
            logging.error("Scan failed: %s", str(e))
            flash("An error occurred while scanning. Please try again.", "danger")

        return redirect(url_for("home"))

    @app.route("/uploads/<path:filename>")
    @login_required
    def uploaded_file(filename):
        # Output encoding to avoid path traversal
        filename = secure_filename(filename)
        return send_from_directory("uploads", filename, as_attachment=False)

  
    # --- Risk Routes ---
    @app.route("/risks")
    @login_required
    def risks():
        session = get_session()
        risks = session.query(Risk).all()
        close_session(session)
        return render_template("risks.html", risks=risks)

    @app.route("/add_risk", methods=["POST"])
    def add_risk():
        session = get_session()
        data = request.form
        risk = Risk(
            asset=data["asset"],
            threat=data["threat"],
            vulnerability=data["vulnerability"],
            control=data["control"],
            compliance_standard=data.get("compliance_standard", "NIST"),
            likelihood=int(data.get("likelihood", 1)),
            impact=int(data.get("impact", 1))
        )
        risk.calculate_score()
        session.add(risk)
        session.commit()
        close_session(session)
        flash("Risk added successfully!", "success")
        return redirect(url_for("risks"))


    # --- Compliance Routes ---
    @app.route("/compliance")
    def compliance():
        session = get_session()
        records = session.query(Compliance).all()
        close_session(session)
        return render_template("compliance.html", compliance=records)

    @app.route("/add_compliance", methods=["POST"])
    def add_compliance():
        session = get_session()
        data = request.form
        compliance = Compliance(
            framework=data["framework"],
            control=data["control"],
            score=float(data.get("score", 0.0)),
            risk_id=int(data.get("risk_id", None))
        )
        session.add(compliance)
        session.commit()
        close_session(session)
        flash("Compliance record added!", "success")
        return redirect(url_for("compliance"))


    # --- Dependency Routes ---
    @app.route("/dependencies")
    def dependencies():
        session = get_session()
        deps = session.query(Dependency).all()
        close_session(session)
        return render_template("dependencies.html", dependencies=deps)

    @app.route("/add_dependency", methods=["POST"])
    def add_dependency():
        session = get_session()
        data = request.form
        dep = Dependency(
            name=data["name"],
            version=data["version"],
            risk=data.get("risk"),
            mitigation=data.get("mitigation", "Upgrade recommended")
        )
        session.add(dep)
        session.commit()
        close_session(session)
        flash("Dependency added!", "success")
        return redirect(url_for("dependencies"))
    

    # error handlers
    @app.errorhandler(404)
    def not_found(e):
        return render_template("errors/404.html"), 404


    @app.errorhandler(500)
    def server_error(e):
        logging.error(f"500 Error: {e}")
        return render_template("errors/500.html"), 500


    return app


# ------------------------------------------------------------------------------
# Utils
# ------------------------------------------------------------------------------
ALLOWED_EXTENSIONS = {".pdf", ".txt"}



def allowed_file(filename: str) -> bool:
    ext = os.path.splitext(filename)[1].lower()
    return ext in ALLOWED_EXTENSIONS


def secure_filename(name: str) -> str:
    # stricter sanitization than werkzeug default
    name = werkzeug_secure(name)
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name)


def json_dumps(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    app = create_app()
    # Avoid debug=True in production
    app.run(debug=False, host="127.0.0.1", port=5000)
