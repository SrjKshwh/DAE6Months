# app.py
"""
Secure GRC Portal - Flask App
This file demonstrates Secure Software Development requirements and Zero Trust Architecture:
- Secure environment (use VS Code extensions SonarLint, GitGuardian, etc.)
- Input validation, output encoding, error handling
- Password hashing & authentication
- Security logging & safe defaults
- Zero Trust: Never trust, always verify - implemented via multiple security layers:
  * Authentication (login_required decorator)
  * Input validation (regex, length checks)
  * Session timeout enforcement (active verification on each request)
  * IP-based access control (restrict access to allowed IPs)
"""

import os
import re
import sqlite3
import json
import logging
import threading
import time
import hashlib
import psutil
from datetime import timedelta, datetime
from pathlib import Path
from functools import wraps

from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename as werkzeug_secure

load_dotenv()

from db import get_engine, get_session, close_session
from models import Base, User, Upload, ScanResult, Risk, Compliance, Dependency, Incident, IncidentStatus, IncidentSeverity, Evidence, EvidenceType
from llm_scan import scan_file_for_grc, create_risks_from_scan

# ------------------------------------------------------------------------------
# Secure Development Environment Notes
# - Ensure VS Code has SonarLint, GitGuardian, Python Security Linter enabled
# - Use a .gitignore to avoid committing secrets/uploads/__pycache__
# - Run Bandit/Safety for static analysis
# ------------------------------------------------------------------------------

# Configure logging will be done in create_app


def compute_file_hash(file_path):
    """Compute SHA-256 hash of a file for integrity verification."""
    hash_sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    except Exception as e:
        logging.error(f"Error computing hash for {file_path}: {e}")
        return None


def collect_forensics_data():
    """Collect forensics data for report"""
    report = "DIGITAL FORENSICS REPORT\n"
    report += "=" * 50 + "\n\n"

    # System Logs
    report += "1. SYSTEM LOGS\n"
    report += "-" * 20 + "\n"
    try:
        with open("logs/forensics.log", "r") as f:
            logs = f.read()
            report += logs if logs else "No logs available.\n"
    except FileNotFoundError:
        report += "Log file not found.\n"
    report += "\n"

    # User Activity (from logs)
    report += "2. USER ACTIVITY\n"
    report += "-" * 20 + "\n"
    # Since logs are already included, perhaps summarize or note it's in logs
    report += "User activities are logged in the system logs above.\n\n"

    # Incident Evidence
    report += "3. INCIDENT EVIDENCE\n"
    report += "-" * 20 + "\n"
    db = get_session()
    incidents = db.query(Incident).all()
    if incidents:
        for inc in incidents:
            report += f"Incident ID: {inc.id}\n"
            report += f"Title: {inc.title}\n"
            report += f"Description: {inc.description}\n"
            report += f"Status: {inc.status.value}\n"
            report += f"Severity: {inc.severity.value}\n"
            report += f"Reported At: {inc.reported_at}\n"
            if inc.preparation_notes:
                report += f"Preparation Notes: {inc.preparation_notes}\n"
            if inc.identification_notes:
                report += f"Identification Notes: {inc.identification_notes}\n"
            if inc.containment_notes:
                report += f"Containment Notes: {inc.containment_notes}\n"
            if inc.eradication_notes:
                report += f"Eradication Notes: {inc.eradication_notes}\n"
            if inc.recovery_notes:
                report += f"Recovery Notes: {inc.recovery_notes}\n"
            report += "\n"
    else:
        report += "No incidents reported.\n"
    close_session(db)
    report += "\n"

    # Evidence Forms
    report += "4. EVIDENCE FORMS\n"
    report += "-" * 20 + "\n"
    report += "a. Logs: Included above.\n"
    db = get_session()
    evidence_list = db.query(Evidence).all()
    if evidence_list:
        for ev in evidence_list:
            report += f"Evidence ID: {ev.id}\n"
            report += f"Type: {ev.type.value}\n"
            report += f"Description: {ev.description}\n"
            report += f"Collected By: {ev.collector.email if ev.collector else 'Unknown'}\n"
            report += f"Collected At: {ev.collected_at}\n"
            report += f"Storage Method: {ev.storage_method}\n"
            if ev.hash_value:
                report += f"Integrity Hash: {ev.hash_value}\n"
            if ev.file_path:
                report += f"File Path: {ev.file_path}\n"
            report += "\n"
    else:
        report += "No evidence collected.\n"
        report += "b. Screenshots: [Placeholder] Screenshots would be captured of the incident scenes, user interfaces, or system states at the time of the incident. For this demo, no actual screenshots are captured.\n"
    close_session(db)
    report += "\n"

    report += "Report generated at: " + str(datetime.now(timezone.utc)) + "\n"
    return report


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
    Path("reports").mkdir(exist_ok=True)
    Path("logs").mkdir(exist_ok=True)
    Path("evidence").mkdir(exist_ok=True)

    # Configure logging (no sensitive info)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler("logs/forensics.log"),
            logging.StreamHandler()
        ]
    )

    # Create a logger for forensics
    forensics_logger = logging.getLogger("forensics")
    forensics_logger.setLevel(logging.INFO)

    # DB init
    engine = get_engine()
    Base.metadata.create_all(engine)

    # teardown hook for DB session
    @app.teardown_appcontext
    def teardown_db(exception=None):
        close_session()

    # Zero Trust: Session timeout enforcement
    # Always verify session validity on each request
    @app.before_request
    def check_session_timeout():
        if 'user_id' in session and 'login_time' in session:
            # Enforce session lifetime (Zero Trust: never trust, always verify)
            if time.time() - session['login_time'] > app.config['PERMANENT_SESSION_LIFETIME'].total_seconds():
                session.clear()
                flash("Session expired due to inactivity. Please login again.", "warning")
                return redirect(url_for("login"))

    # Zero Trust: IP-based access control
    # Restrict access to allowed IPs (Zero Trust: verify every access)
    ALLOWED_IPS = os.getenv("ALLOWED_IPS", "127.0.0.1").split(",")
    @app.before_request
    def check_ip_restriction():
        if request.endpoint not in ['login', 'register', 'static'] and request.remote_addr not in ALLOWED_IPS:
            flash("Access denied from this IP address.", "danger")
            return redirect(url_for("login"))

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
            # Zero Trust: Verify user authentication on every protected request
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
            # Zero Trust: Input validation - sanitize and validate all user inputs
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
                session['login_time'] = time.time()  # Zero Trust: Track session start for timeout enforcement
                forensics_logger.info(f"User {user.email} logged in successfully from IP {request.remote_addr}")
                return redirect(url_for("home"))
            else:
                flash("Invalid credentials.", "danger")

        return render_template("login.html")

    @app.route("/logout")
    def logout():
        user_id = session.get("user_id")
        if user_id:
            db = get_session()
            user = db.get(User, user_id)
            if user:
                forensics_logger.info(f"User {user.email} logged out from IP {request.remote_addr}")
            close_session(db)
        session.clear()
        flash("Logged out securely.", "info")
        return redirect(url_for("login"))

    @app.route("/home", methods=["GET", "POST"])
    @login_required
    def home():
        user = current_user()
        db = get_session()        
        # Check if user wants to clear previous details
        show_previous = 'clear' not in request.args
        # Get last upload for scan button and show recent scan results (only if not clearing)
        last_upload = None
        has_scan = False
        scan_result = None
        if show_previous:
            last_upload = (
                db.query(Upload)
                .filter(Upload.user_id == user.id)
                .order_by(Upload.id.desc())
                .first()
            )
            has_scan = last_upload.scan_result is not None if last_upload else False
            scan_result = last_upload.scan_result if last_upload and has_scan else None

        # File upload (with validation) 
        # Perimeter: IP/session validation (handled by before_request)
        # Application: User authentication and input validation         
        if request.method == "POST" and "file" in request.files:
            file = request.files["file"]
            if not file or not file.filename:
                flash("No file selected. Please choose a file.", "danger")
            elif not allowed_file(file.filename):
                flash("Invalid file type. Allowed: .pdf, .txt", "danger")
            else:
                try:
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

                    forensics_logger.info(f"User {user.email} uploaded file {filename} from IP {request.remote_addr}")

                    # Schedule file deletion after 2 minutes (120 seconds)
                    delete_file_after_delay(save_path, 120)

                    flash("File uploaded securely.", "success")
                    return redirect(url_for("home"))
                except Exception as e:
                    logging.error(f"Error uploading file: {e}")
                    flash("Error uploading file. Please try again.", "danger")
                    db.rollback()


        compliance_hits = []
        risks_list = []
        if show_previous and  scan_result:
            try:
                compliance_hits = json.loads(scan_result.compliance_hits_json or '[]')
                risks_list = [
                    {"risk": risk.threat, "severity": risk.severity.value}
                    for risk in scan_result.risks
                    ]
            except json.JSONDecodeError as e:
                logging.error(f"Failed to parse scan result JSON: {e}")


        # Provide variables for scan button and show current scan results
        return render_template(
            "home.html",
            user=user,
            last_upload=last_upload,  # Needed for scan button
            has_scan=has_scan,        # Needed to disable scan button if already scanned
            scan_result=scan_result,  # Show scan results after scanning
            compliance_hits=compliance_hits,
            risks=risks_list,
            show_previous=show_previous,
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
       

    # ------------------------
    # Secure Scan Route
    # ------------------------
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

            # Generate and store risk entries from scan results
            risks_data = data.get("risks", [])
            compliance_data = data.get("compliance_hits", [])
            if risks_data:
                create_risks_from_scan(res.id, risks_data, compliance_data)

            forensics_logger.info(f"User {session.get('user_id')} scanned file {up.filename}")
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

    @app.route("/evidence/<path:filename>")
    @login_required
    def evidence_file(filename):
        # Output encoding to avoid path traversal
        filename = secure_filename(filename)
        return send_from_directory("evidence", filename, as_attachment=True)

  
    # --- Risk Routes ---
    @app.route("/risks")
    @login_required
    def risks():
        session = get_session()
        user = current_user()
        # Get risks associated with user's scan results
        user_risks = (session.query(Risk).join(ScanResult).join(Upload).filter(Upload.user_id == user.id).all())
        close_session(session)
        return render_template("risks.html", risks=user_risks)

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
        # Assess risks for each dependency
        for dep in deps:
            dep.assess_risk()
        close_session(session)
        return render_template("dependencies.html", dependencies=deps)

    @app.route("/add_dependency", methods=["POST"])
    def add_dependency():
        session = get_session()
        data = request.form
        dep = Dependency(
            name=data["name"],
            version=data["version"],
            risk=data.get("risk", ""),
            mitigation=data.get("mitigation", "Upgrade recommended"),
            risk_level=RiskSeverity.LOW,  # default
            vulnerabilities=None,
            mitigation_suggestions=None
        )
        # Assess risk based on name and version
        dep.assess_risk()
        session.add(dep)
        session.commit()
        close_session(session)
        flash("Dependency added with risk assessment!", "success")
        return redirect(url_for("dependencies"))

    # --- Security Policies Route ---
    @app.route("/policies")
    @login_required
    def policies():
        return render_template("policies.html")

    # --- Knowledge Base Route ---
    @app.route("/kb")
    @login_required
    def kb():
        return render_template("kb.html")

    # --- SOC Monitoring Route ---
    @app.route("/monitoring")
    @login_required
    def monitoring():
        # System monitoring using psutil
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        network = psutil.net_io_counters()

        # Recent security events from logs
        security_events = []
        try:
            with open("logs/forensics.log", "r") as f:
                lines = f.readlines()[-10:]  # Last 10 log entries
                security_events = [line.strip() for line in lines]
        except FileNotFoundError:
            security_events = ["No security logs available"]

        # Active incidents
        db = get_session()
        active_incidents = db.query(Incident).filter(Incident.status != IncidentStatus.CLOSED).all()
        close_session(db)

        return render_template("monitoring.html",
                             cpu_percent=cpu_percent,
                             memory=memory,
                             disk=disk,
                             network=network,
                             security_events=security_events,
                             active_incidents=active_incidents)

    # --- Incident Routes ---
    @app.route("/incidents")
    @login_required
    def incidents():
        db = get_session()
        user_incidents = db.query(Incident).filter(Incident.reported_by == session.get("user_id")).all()
        close_session(db)
        return render_template("incidents.html", incidents=user_incidents)

    @app.route("/report_incident", methods=["GET", "POST"])
    @login_required
    def report_incident():
        if request.method == "POST":
            title = request.form.get("title")
            description = request.form.get("description")
            severity = request.form.get("severity", IncidentSeverity.MEDIUM.value)
            db = get_session()
            incident = Incident(
                title=title,
                description=description,
                severity=IncidentSeverity(severity),
                reported_by=session.get("user_id")
            )
            db.add(incident)
            db.commit()
            forensics_logger.info(f"User {session.get('user_id')} reported incident '{title}' with severity {severity}")
            close_session(db)
            flash("Incident reported successfully.", "success")
            return redirect(url_for("incidents"))
        return render_template("report_incident.html", severities=IncidentSeverity)

    @app.route("/incident/<int:incident_id>", methods=["GET", "POST"])
    @login_required
    def view_incident(incident_id):
        db = get_session()
        incident = db.query(Incident).filter(Incident.id == incident_id, Incident.reported_by == session.get("user_id")).first()
        if not incident:
            close_session(db)
            flash("Incident not found.", "danger")
            return redirect(url_for("incidents"))
        if request.method == "POST":
            # Update notes and status
            incident.preparation_notes = request.form.get("preparation_notes")
            incident.identification_notes = request.form.get("identification_notes")
            incident.containment_notes = request.form.get("containment_notes")
            incident.eradication_notes = request.form.get("eradication_notes")
            incident.recovery_notes = request.form.get("recovery_notes")
            status = request.form.get("status")
            if status and status == IncidentStatus.CLOSED.value:
                # Generate post-incident analysis
                analysis = f"""
                    Incident Summary: {incident.title}
                    Outcome: {incident.status.value}
                    Lessons Learned:
                    1. Enhanced monitoring could prevent similar incidents
                    2. Regular security training reduces human error risk
                    3. Backup systems ensure business continuity
                    4. Incident response procedures need regular testing
                    5. Communication protocols should be improved
                    """
                # Store analysis in incident or generate report
                incident.analysis = analysis  # Would need to add analysis field to Incident model
            db.commit()
            forensics_logger.info(f"User {session.get('user_id')} updated incident {incident_id} status to {status}")
            flash("Incident updated.", "success")
        close_session(db)
        return render_template("incident.html", incident=incident, statuses=IncidentStatus, severities=IncidentSeverity)


    # --- Forensics Route ---
    @app.route("/forensics", methods=["GET", "POST"])
    @login_required
    def forensics():
        db = get_session()
        user = current_user()
        if request.method == "POST":
            if "generate_report" in request.form:
                # Collect data and generate report
                report_content = collect_forensics_data()
                # Save report to file
                report_filename = f"forensics_report_{int(time.time())}.txt"
                report_path = os.path.join("reports", report_filename)
                with open(report_path, "w") as f:
                    f.write(report_content)
                forensics_logger.info(f"Forensics report generated: {report_filename}")
                # Send file for download
                close_session(db)
                return send_from_directory("reports", report_filename, as_attachment=True, download_name=report_filename)
            elif "collect_evidence" in request.form:
                # Collect evidence
                evidence_type = request.form.get("evidence_type")
                description = request.form.get("description")
                storage_method = request.form.get("storage_method", "Secure server storage")
                incident_id = request.form.get("incident_id")

                file_path = None
                hash_value = None
                if "evidence_file" in request.files:
                    file = request.files["evidence_file"]
                    if file and file.filename:
                        if not allowed_file(file.filename):
                            flash("Invalid file type for evidence. Allowed: .pdf, .txt, .log, .png, .jpg, .jpeg", "danger")
                            close_session(db)
                            return redirect(url_for("forensics"))
                        filename = secure_filename(file.filename)
                        evidence_dir = "evidence"
                        Path(evidence_dir).mkdir(exist_ok=True)
                        file_path = os.path.join(evidence_dir, filename)
                        file.save(file_path)
                        hash_value = compute_file_hash(file_path)
                        forensics_logger.info(f"Evidence file uploaded: {file_path}")

                evidence = Evidence(
                    type=EvidenceType(evidence_type),
                    file_path=file_path,
                    description=description,
                    collected_by=user.id,
                    storage_method=storage_method,
                    hash_value=hash_value,
                    incident_id=int(incident_id) if incident_id else None
                )
                db.add(evidence)
                db.commit()
                forensics_logger.info(f"Evidence collected by {user.email}: {evidence_type}")
                flash("Evidence collected successfully.", "success")

        # Get incidents for dropdown
        incidents = db.query(Incident).filter(Incident.reported_by == user.id).all()
        # Get collected evidence
        evidence_list = db.query(Evidence).filter(Evidence.collected_by == user.id).all()
        close_session(db)
        return render_template("forensics.html", incidents=incidents, evidence=evidence_list, evidence_types=EvidenceType)


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
ALLOWED_EXTENSIONS = {".pdf", ".txt", ".log", ".png", ".jpg", ".jpeg"}



def allowed_file(filename: str) -> bool:
    ext = os.path.splitext(filename)[1].lower()
    return ext in ALLOWED_EXTENSIONS


def secure_filename(name: str) -> str:
    # stricter sanitization than werkzeug default
    name = werkzeug_secure(name)
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name)


def json_dumps(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2)


def delete_file_after_delay(file_path: str, delay_seconds: int = 120):
    """Delete a file after a specified delay in seconds."""
    def delete():
        time.sleep(delay_seconds)
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                logging.info(f"File {file_path} deleted after {delay_seconds} seconds.")
        except Exception as e:
            logging.error(f"Error deleting file {file_path}: {e}")

    # Start the deletion in a background thread
    thread = threading.Thread(target=delete)
    thread.daemon = True
    thread.start()


if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        # Seed admin user if none exists
        engine = get_engine()
        with engine.begin() as conn:
            if conn.exec_driver_sql("SELECT COUNT(*) FROM users").scalar() == 0:
                pw = generate_password_hash("Sksf1234")  # hashed
                conn.exec_driver_sql(
                    "INSERT INTO users (email, password_hash, is_verified) VALUES (:e, :p, :v)",
                    {"e": "kush786srj@gmail.com", "p": pw, "v": True},
                )
                logging.info("Default admin user created")

            # Seed sample dependencies for demo
            # Commented out due to schema mismatch
            # if conn.exec_driver_sql("SELECT COUNT(*) FROM dependencies").scalar() == 0:
            #     # Use ORM for proper defaults
            #     session = get_session()
            #     dep1 = Dependency(name="Flask", version="1.1.4")
            #     dep1.assess_risk()
            #     session.add(dep1)
            #     dep2 = Dependency(name="requests", version="2.20.0")
            #     dep2.assess_risk()
            #     session.add(dep2)
            #     dep3 = Dependency(name="sqlalchemy", version="1.4.0")
            #     dep3.assess_risk()
            #     session.add(dep3)
            #     session.commit()
            #     close_session(session)
            #     logging.info("Sample dependencies added for demo")
    # Avoid debug=True in production
    app.run(debug=False, host="127.0.0.1", port=5000)
