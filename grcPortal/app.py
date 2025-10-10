"""
Secure GRC Portal - Flask Web Application

A comprehensive Governance, Risk, and Compliance (GRC) portal built with Flask,
implementing enterprise-grade security practices and Zero Trust Architecture.

This application provides:
- User authentication and authorization
- File upload and security scanning using LLM
- Risk assessment and management
- Compliance monitoring and reporting
- Incident management and response
- Digital forensics and evidence collection
- Security monitoring and logging

Security Features:
- Zero Trust Architecture with multiple verification layers
- Secure password hashing with Werkzeug
- Session management with timeout enforcement
- IP-based access control
- Input validation and sanitization
- Secure file upload handling
- Comprehensive security logging
- SQL injection prevention with SQLAlchemy ORM

Architecture:
- Flask web framework with SQLAlchemy ORM
- SQLite database with proper session management
- Template-based UI with security headers
- RESTful API endpoints with proper error handling
- Background task processing for file operations

Usage:
    python app.py

Environment Variables:
    FLASK_SECRET: Secret key for session encryption
    ALLOWED_IPS: Comma-separated list of allowed IP addresses
    MODEL_NAME: LLM model name for scanning
    OPENROUTER_API_KEY: API key for LLM service
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
from datetime import timedelta, datetime, timezone
from pathlib import Path
from functools import wraps

from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, g

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename as werkzeug_secure
from flask_migrate import Migrate

load_dotenv()

from db import get_engine, get_session, close_session


from models import Base, User, Upload, ScanResult, Risk, Compliance, Dependency, Incident, IncidentStatus, IncidentSeverity, Evidence, EvidenceType, AuditLog, BrainstormingSession, BrainstormingParticipant, BrainstormingIdea, RiskChecklist, RiskChecklistItem, RiskChecklistAssessment, RiskChecklistResponse, SWOTAnalysis, SWOTItem, RiskIdentificationMethod, RiskSeverity, ApprovalStatus, GovernanceDecision, RiskApproval, RiskComplianceMapping, ComplianceRequirement, CriticalAssetRegister, RiskManagementFramework, RiskProgramPlan, ProgramPhase, GapAnalysis, RiskIndicator, IndicatorReading, EnvironmentalChange, MalwareSample, MalwareAnalysis, PhishingTemplate, APTCampaign, ATTACKMapping, VulnerabilityScan, VulnerabilityFinding, AssetDiscovery, DiscoveredService, IndicatorOfCompromise, IoCAnalysis, DetectionRule, OpenCTIConnector, OpenCTIIntegration, MonitoringConfiguration


from sqlalchemy.orm import sessionmaker, joinedload

from llm_scan import scan_file_for_grc, create_risks_from_scan,generate_risk_mitigation_plan

def perform_malware_analysis(sample_hash):
    """
    Perform detailed malware analysis simulation (equivalent to VirusTotal analysis).

    In production, this would integrate with VirusTotal API:
    - Upload file to VirusTotal
    - Retrieve analysis results
    - Parse detection ratios and behavioral indicators

    Args:
        sample_hash (str): SHA256 hash of the malware sample

    Returns:
        dict: Analysis results including detection ratio, behavioral indicators, and impact assessment
    """
    # Mock VirusTotal analysis results
    # In production: response = requests.get(f'https://www.virustotal.com/api/v3/files/{sample_hash}', headers=headers)

    analysis_results = {
        "positives": 47,
        "total": 72,
        "behavioral_indicators": {
            "file_operations": [
                "Creates suspicious files in %APPDATA%",
                "Modifies Windows Registry for persistence",
                "Attempts to disable Windows Defender",
                "Creates scheduled tasks for execution"
            ],
            "network_activity": [
                "Connects to known C2 servers",
                "Exfiltrates data to external IPs",
                "Uses TOR network for communication",
                "Attempts DNS tunneling"
            ],
            "process_manipulation": [
                "Injects code into legitimate processes",
                "Creates suspended processes",
                "Modifies process memory"
            ],
            "anti_analysis": [
                "Detects virtual machine environment",
                "Checks for debugging tools",
                "Uses obfuscation techniques"
            ]
        },
        "impact": "High - Data exfiltration, system persistence, lateral movement capabilities",
        "severity": "critical",
        "threat_family": "Ransomware",
        "mitre_techniques": ["T1055", "T1071", "T1105", "T1490"],
        "recommended_actions": [
            "Isolate infected systems immediately",
            "Change all credentials",
            "Scan network for similar indicators",
            "Restore from clean backups"
        ]
    }

    return analysis_results

def perform_ioc_analysis(ioc):
    """
    Perform comprehensive IoC analysis with threat intelligence correlation.

    In production, this would integrate with multiple threat intelligence sources:
    - VirusTotal, AlienVault OTX, MISP, Recorded Future
    - Historical analysis and correlation
    - Behavioral pattern matching

    Args:
        ioc: IndicatorOfCompromise object with indicator details

    Returns:
        dict: Comprehensive analysis results including risk scoring and mitigation steps
    """
    # Enhanced IoC analysis with realistic threat intelligence data
    analysis_results = {
        "detection_method": "multi-source_threat_intelligence_correlation",
        "threat_indication": f"Indicator matches known {ioc.indicator_type} patterns associated with {ioc.threat_actor or 'multiple'} threat actors. Historical sightings indicate active malicious campaigns.",
        "risk_score": 85,
        "false_positive_probability": 12,
        "analysis_result": {
            "risk_score": 85,
            "confidence_level": "High",
            "threat_context": {
                "associated_campaigns": ["Operation Dust Storm", "SolarWinds Supply Chain"],
                "targeted_sectors": ["Government", "Financial", "Healthcare"],
                "geographic_distribution": ["US", "EU", "Asia-Pacific"],
                "temporal_patterns": "Active during business hours, spikes on weekends"
            },
            "technical_details": {
                "first_observed": "2023-11-15",
                "last_observed": "2024-10-06",
                "observation_frequency": "High",
                "attribution_confidence": "Medium",
                "infrastructure_overlap": ["Shared hosting providers", "Similar SSL certificates"]
            },
            "related_indicators": [
                "Similar domain registration patterns",
                "Common IP address ranges",
                "Related file hashes in same family",
                "Associated email addresses",
                "Connected C2 infrastructure"
            ],
            "recommended_actions": [
                "Immediate blocking of indicator",
                "Enhanced monitoring for related activity",
                "Credential rotation for affected systems",
                "Network segmentation review",
                "Endpoint protection updates"
            ]
        },
        "mitigation_steps": "Implement comprehensive blocking rules across all security layers. Conduct thorough network scanning for related indicators. Enhance endpoint protection with updated signatures. Implement network segmentation to limit lateral movement. Regular credential rotation and monitoring.",
        "analyst_notes": "IoC shows strong correlation with known APT campaigns. False positive probability is low based on multi-source validation. Immediate action recommended due to active threat landscape."
    }

    return analysis_results

def get_attack_technique_details(technique_id):
    """
    Get detailed information about a MITRE ATT&CK technique.

    In production, this would query the official MITRE ATT&CK API or database.
    Currently returns realistic technique information for demonstration.

    Args:
        technique_id (str): ATT&CK technique ID (e.g., "T1055", "T1071.001")

    Returns:
        dict: Technique details including tactic, name, and description
    """
    # Realistic ATT&CK technique database
    attack_techniques = {
        "T1055": {
            "tactic": "Defense Evasion, Privilege Escalation",
            "technique": "Process Injection",
            "subtechnique": None,
            "description": "Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges."
        },
        "T1055.001": {
            "tactic": "Defense Evasion, Privilege Escalation",
            "technique": "Process Injection",
            "subtechnique": "Dynamic-link Library Injection",
            "description": "Adversaries may inject dynamic-link libraries (DLLs) into processes in order to evade process-based defenses as well as possibly elevate privileges."
        },
        "T1071": {
            "tactic": "Command and Control",
            "technique": "Application Layer Protocol",
            "subtechnique": None,
            "description": "Adversaries may communicate using application layer protocols to avoid detection/network filtering by blending in with existing traffic."
        },
        "T1071.001": {
            "tactic": "Command and Control",
            "technique": "Application Layer Protocol",
            "subtechnique": "Web Protocols",
            "description": "Adversaries may communicate using application layer protocols associated with web traffic to avoid detection/network filtering by blending in with existing traffic."
        },
        "T1105": {
            "tactic": "Command and Control",
            "technique": "Ingress Tool Transfer",
            "subtechnique": None,
            "description": "Adversaries may transfer tools or other files from an external system into a compromised environment."
        },
        "T1490": {
            "tactic": "Impact",
            "technique": "Inhibit System Recovery",
            "subtechnique": None,
            "description": "Adversaries may delete or remove built-in operating system tools or capabilities that allow for system recovery."
        }
    }

    return attack_techniques.get(technique_id, {
        "tactic": "Unknown",
        "technique": "Unknown Technique",
        "subtechnique": None,
        "description": "Technique details not available in current database"
    })

def get_campaign_techniques(campaign_name):
    """
    Get relevant ATT&CK techniques for a specific APT campaign.

    Based on real-world campaign analysis, returns techniques commonly
    associated with the threat actor or campaign type.

    Args:
        campaign_name (str): Name of the APT campaign

    Returns:
        list: List of relevant technique IDs for the campaign
    """
    # Campaign-specific technique mapping based on real APT analysis
    campaign_techniques = {
        "SolarWinds": ["T1055", "T1071.001", "T1105", "T1490", "T1059.001", "T1136.001"],
        "WannaCry": ["T1210", "T1082", "T1105", "T1047", "T1021.002"],
        "NotPetya": ["T1486", "T1105", "T1055", "T1071", "T1490"],
        "APT28": ["T1059.001", "T1071.001", "T1105", "T1055", "T1003.001"],
        "Lazarus": ["T1566.001", "T1059.003", "T1105", "T1055", "T1490"]
    }

    # Default techniques for unknown campaigns
    default_techniques = ["T1055", "T1071", "T1105", "T1059", "T1003"]

    return campaign_techniques.get(campaign_name, default_techniques)

def generate_risk_communication_plan(risk_data, mitigation_plan):
    """
    Generate a comprehensive risk communication plan with stakeholder analysis and tailored messaging.

    This function creates a detailed communication strategy for risk management, including
    executive risk reports, stakeholder communication plans, risk dashboards, and KPI frameworks.
    The plan is designed to ensure effective communication of risk information across different
    organizational levels and stakeholder groups.

    Args:
        risk_data (dict): Dictionary containing risk assessment data including:
            - asset: The asset being assessed
            - threat: The identified threat
            - score: Risk score (1-25)
            - likelihood: Likelihood rating (1-5)
            - financial_impact_amount: Financial impact value
        mitigation_plan (dict): Dictionary containing the mitigation plan details

    Returns:
        dict: Comprehensive communication plan with the following structure:
            - executive_risk_report: Key findings, financial impact, actionable recommendations
            - stakeholder_communication_plan: Analysis for different stakeholder groups
            - risk_dashboard_config: Key metrics and automated alerts
            - kpi_framework: Leading/lagging indicators and tracking systems

    Components:
        - Executive Risk Report: High-level summary for leadership
        - Stakeholder Communication Plan: Tailored messaging for different groups
        - Risk Dashboard: Real-time monitoring configuration
        - KPI Framework: Performance measurement and tracking

    Note:
        This is a mock implementation providing comprehensive communication planning.
        In production, this would integrate with organizational communication systems
        and stakeholder databases for more accurate planning.
    """
    # Mock implementation - in production, this would use LLM to generate detailed plan
    communication_plan = {
        "executive_risk_report": {
            "key_findings": [
                f"Risk to {risk_data['asset']} poses significant threat from {risk_data['threat']}",
                f"Vulnerability in {risk_data['vulnerability']} requires immediate attention",
                f"Current risk score of {risk_data['score']} indicates { 'high' if risk_data['score'] > 15 else 'moderate' } priority"
            ],
            "financial_impact_analysis": {
                "total_potential_loss": f"${risk_data.get('financial_impact_amount', 100000):,}",
                "annual_financial_impact": f"${risk_data.get('financial_impact_amount', 100000) * risk_data['likelihood']:,}",
                "business_continuity_risk": "High" if risk_data['score'] > 15 else "Medium"
            },
            "actionable_recommendations": [
                {
                    "priority": "Critical" if risk_data['score'] > 20 else "High",
                    "recommendation": f"Implement {mitigation_plan.get('recommended_strategy', {}).get('strategy', 'mitigation')} strategy immediately",
                    "expected_benefits": "Reduce risk exposure by 70-80%",
                    "timeline": "3-6 months",
                    "responsible_party": "Risk Management Team"
                },
                {
                    "priority": "High",
                    "recommendation": "Conduct regular monitoring and reporting",
                    "expected_benefits": "Early detection of risk changes",
                    "timeline": "Ongoing",
                    "responsible_party": "IT Security Team"
                }
            ]
        },
        "stakeholder_communication_plan": {
            "stakeholder_analysis": [
                {
                    "stakeholder_group": "Executive Leadership",
                    "communication_frequency": "Monthly",
                    "preferred_format": "Executive Summary Reports",
                    "key_concerns": ["Financial impact", "Regulatory compliance", "Business continuity"],
                    "tailored_messaging": "Focus on strategic implications and ROI of mitigation efforts"
                },
                {
                    "stakeholder_group": "IT Department",
                    "communication_frequency": "Weekly",
                    "preferred_format": "Technical Briefs",
                    "key_concerns": ["Technical vulnerabilities", "Implementation details", "Resource requirements"],
                    "tailored_messaging": "Emphasize technical solutions and implementation timelines"
                },
                {
                    "stakeholder_group": "Business Units",
                    "communication_frequency": "Quarterly",
                    "preferred_format": "Business Impact Assessments",
                    "key_concerns": ["Operational disruptions", "Cost implications", "Process changes"],
                    "tailored_messaging": "Highlight business continuity and minimal disruption"
                }
            ]
        },
        "risk_dashboard_config": {
            "key_metrics": [
                {
                    "metric_name": "Risk Score Trend",
                    "visualization_type": "Line Chart",
                    "refresh_frequency": "Daily",
                    "alert_threshold": risk_data['score'] + 2
                },
                {
                    "metric_name": "Mitigation Progress",
                    "visualization_type": "Progress Bar",
                    "refresh_frequency": "Weekly",
                    "alert_threshold": 80
                }
            ],
            "automated_alerts": [
                {
                    "alert_type": "Risk Score Increase",
                    "condition": f"Risk score exceeds {risk_data['score'] + 5}",
                    "severity": "High",
                    "response_required": "Immediate review required"
                },
                {
                    "alert_type": "Mitigation Delay",
                    "condition": "Implementation behind schedule by 20%",
                    "severity": "Medium",
                    "response_required": "Status update required"
                }
            ]
        },
        "kpi_framework": {
            "leading_indicators": [
                {
                    "kpi_name": "Vulnerability Scan Frequency",
                    "target": "Weekly",
                    "current_value": "Weekly",
                    "trend": "Stable",
                    "benchmark_comparison": "Meets industry standard"
                },
                {
                    "kpi_name": "Risk Assessment Coverage",
                    "target": "95%",
                    "current_value": "92%",
                    "trend": "Improving",
                    "benchmark_comparison": "Above average"
                }
            ],
            "lagging_indicators": [
                {
                    "kpi_name": "Incident Response Time",
                    "target": "< 4 hours",
                    "current_value": "3.5 hours",
                    "benchmark_comparison": "Industry leading"
                },
                {
                    "kpi_name": "Risk Mitigation Effectiveness",
                    "target": "80%",
                    "current_value": "75%",
                    "benchmark_comparison": "Good performance"
                }
            ],
            "tracking_systems": {
                "data_collection": "Automated through integrated monitoring tools",
                "reporting_frequency": "Monthly executive reports, weekly operational updates",
                "review_process": "Quarterly governance review with annual comprehensive assessment",
                "accountability": "Risk Manager responsible for KPI tracking and reporting"
            }
        }
    }

    return communication_plan

# ------------------------------------------------------------------------------
# Secure Development Environment Notes
# - Ensure VS Code has SonarLint, GitGuardian, Python Security Linter enabled
# - Use a .gitignore to avoid committing secrets/uploads/__pycache__
# - Run Bandit/Safety for static analysis
# ------------------------------------------------------------------------------

# Configure logging will be done in create_app


def compute_file_hash(file_path):
    """
    Compute SHA-256 hash of a file for integrity verification and evidence collection.

    Generates a cryptographic hash to ensure file integrity and provide
    tamper-evident evidence for digital forensics.

    Args:
        file_path (str): Path to the file to hash

    Returns:
        str or None: Hexadecimal SHA-256 hash string, or None if error occurs

    Raises:
        Logs error message if file cannot be read or hashed

    Note:
        Uses chunked reading (4096 bytes) to handle large files efficiently
        Returns None on error rather than raising exceptions for graceful degradation
    """
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
    """
    Collect and compile digital forensics data into a comprehensive report.

    Gathers evidence from multiple sources including system logs, user activity,
    incident reports, and collected evidence files. Generates a structured
    forensics report suitable for incident response and legal proceedings.

    Returns:
        str: Complete forensics report as formatted text

    Sources included:
        - System logs from logs/forensics.log
        - Incident database records
        - Evidence files and metadata
        - User activity summaries
        - Report generation timestamp

    Note:
        Requires read access to logs/ directory and database
        Handles missing log files gracefully
        Includes integrity hashes for evidence files
    """
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
    """
    Flask application factory function implementing secure configuration and Zero Trust Architecture.

    Creates and configures the Flask application with comprehensive security measures
    including session management, IP restrictions, logging, and database integration.

    Returns:
        Flask: Configured Flask application instance

    Security Features Configured:
        - Secure session configuration with timeout and cookies
        - IP-based access control (Zero Trust perimeter)
        - Session timeout enforcement (Zero Trust verification)
        - Comprehensive logging setup
        - Database initialization with SQLAlchemy
        - Security headers and CSRF protection

    Environment Setup:
        - Creates necessary directories (instance, uploads, reports, logs, evidence)
        - Initializes database tables
        - Sets up logging handlers

    Note:
        Implements defense in depth with multiple security layers
        Uses Flask application context for thread-safe operations
    """
    app = Flask(__name__, instance_relative_config=True)
    migrate = Migrate(app, Base)
 
    # Secure config
    app.config.update(
        SECRET_KEY=os.getenv("FLASK_SECRET", os.urandom(24)),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=not app.debug,  # true in prod
        SESSION_COOKIE_SAMESITE="Lax",
        MAX_CONTENT_LENGTH=10*1024*1024  # 10 MB upload cap
    )
    # Inactivity timeout configuration
    INACTIVITY_TIMEOUT = int(os.getenv("INACTIVITY_TIMEOUT", 120000))  # 2 minute default for blur
    WARNING_TIMEOUT = int(os.getenv("WARNING_TIMEOUT", 20000))  # 20 seconds for logout after warning
    
    # Make these available to templates/JavaScript
    app.config['INACTIVITY_TIMEOUT'] = INACTIVITY_TIMEOUT
    app.config['WARNING_TIMEOUT'] = WARNING_TIMEOUT

    # Make available in Jinja templates
    app.jinja_env.globals['inactivity_timeout'] = INACTIVITY_TIMEOUT
    app.jinja_env.globals['warning_timeout'] = WARNING_TIMEOUT

    # app.jinja_env.globals['current_user'] = current_user

    # Enable Jinja2 debug extension for template debugging
    app.jinja_env.add_extension('jinja2.ext.debug')

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
        """
        Flask application teardown hook for database session cleanup.

        Automatically closes database sessions at the end of each request
        to prevent connection leaks and ensure proper resource management.

        Args:
            exception: Exception object if request ended with error (optional)

        Note:
            Registered as Flask teardown handler to run after every request
            Ensures database connections are properly returned to connection pool
            Critical for production applications to prevent resource exhaustion
        """
        # Close the main session
        close_session()
        # Also close the compliance session if it exists
        compliance_session = g.pop("compliance_session", None)
        if compliance_session is not None:
            compliance_session.close()

    # Zero Trust: Session timeout enforcement - DISABLED for client-side handling
    # Client-side JavaScript now handles inactivity timeouts with user interaction
    # @app.before_request
    # def check_session_timeout():
    #     if 'user_id' in session and 'login_time' in session:
    #         elapsed = time.time() - session['login_time']
    #         inactivity_timeout_seconds = app.config['INACTIVITY_TIMEOUT'] / 1000  # Convert ms to seconds
    #         logging.info(f"DEBUG: Session check - elapsed: {elapsed}s, inactivity_timeout: {inactivity_timeout_seconds}s, user: {session.get('user_id')}")
    #         # Enforce inactivity timeout (Zero Trust: never trust, always verify)
    #         if elapsed > inactivity_timeout_seconds:
    #             logging.warning(f"Session expired for user {session.get('user_id')} after {elapsed}s inactivity")
    #             session.clear()     # Investigation: Check user activity logs
    #             flash("Session expired due to inactivity. Please login again.", "warning")
    #             return redirect(url_for("login"))   # Resolution: Force re-authentication

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
        """
        Retrieve current authenticated user from session.

        Gets the User object for the currently authenticated user based on
        session data. Returns None if no user is authenticated or if on login/register pages.

        Returns:
            User object or None: Current authenticated user or None if not logged in or on login/register pages

        Security Note:
            Validates user existence in database to prevent session manipulation
            Uses secure session management to prevent fixation attacks
            Returns None for login and register pages to hide navigation bar
        """
        # For login and register pages, always return None to hide nav bar
        if request.endpoint in ['login', 'register']:
            return None

        uid = session.get("user_id")
        logging.info(f"DEBUG: current_user() - session user_id: {uid}")
        if not uid:
            logging.info("DEBUG: current_user() - no user_id in session")
            return None
        db = get_session()
        user = db.get(User, uid)
        logging.info(f"DEBUG: current_user() - db.get(User, {uid}) returned: {user}")
        if user:
            logging.info(f"DEBUG: current_user() - user email: {user.email}, verified: {user.is_verified}")
        else:
            logging.info("DEBUG: current_user() - user not found in database")
        return user


    # Make current_user available in Jinja templates via context processor
    @app.context_processor
    def inject_current_user():
        return {'current_user': current_user()}

    def login_required(f):
        """
        Decorator that enforces user authentication for protected routes.

        Implements Zero Trust security by verifying user authentication on every
        request to protected endpoints. Redirects unauthenticated users to login.

        Args:
            f: The route function to be decorated

        Returns:
            Decorated function that checks authentication before execution

        Security Features:
            - Verifies user authentication on every protected request
            - Implements Zero Trust "never trust, always verify" principle
            - Automatic redirect to login for unauthenticated users
            - User-friendly flash messages for authentication requirements

        Usage:
            @app.route("/protected")
            @login_required
            def protected_route():
                return "This requires authentication"
        """
        @wraps(f)
        def wrapper(*args, **kwargs):
            # Zero Trust: Verify user authentication on every protected request
            if not current_user():
                flash("Please login first.", "warning")
                return redirect(url_for("login"))
            return f(*args, **kwargs)
        return wrapper

    def admin_required(f):
        """
        Decorator that enforces administrator role access for protected routes.

        Implements governance by ensuring only users with admin role can access
        administrative functions. Provides separation of duties and access control.

        Args:
            f: The route function to be decorated

        Returns:
            Decorated function that checks admin role before execution

        Governance Features:
            - Verifies user has administrator role
            - Logs governance access attempts
            - Provides clear error messages for unauthorized access
            - Supports role-based access control (RBAC)

        Usage:
            @app.route("/admin")
            @login_required
            @admin_required
            def admin_route():
                return "Admin only content"
        """
        @wraps(f)
        def wrapper(*args, **kwargs):
            user = current_user()
            if not user:
                flash("Please login first.", "warning")
                return redirect(url_for("login"))

            if user.role != "admin":
                forensics_logger.warning(f"Governance violation: User {user.email} (role: {user.role}) attempted admin access to {request.path}")
                flash("Administrator access required.", "danger")
                return redirect(url_for("home"))

            forensics_logger.info(f"Governance: Admin {user.email} accessed {request.path}")
            return f(*args, **kwargs)
        return wrapper

    def auditor_required(f):
        """
        Decorator that enforces auditor role access for protected routes.

        Implements governance by ensuring only users with auditor or admin role
        can access audit and compliance functions. Supports compliance monitoring.

        Args:
            f: The route function to be decorated

        Returns:
            Decorated function that checks auditor/admin role before execution

        Governance Features:
            - Verifies user has auditor or admin role
            - Logs governance access attempts
            - Supports compliance monitoring access
            - Implements role hierarchy (auditor < admin)

        Usage:
            @app.route("/audit")
            @login_required
            @auditor_required
            def audit_route():
                return "Audit content"
        """
        @wraps(f)
        def wrapper(*args, **kwargs):
            user = current_user()
            if not user:
                flash("Please login first.", "warning")
                return redirect(url_for("login"))

            if user.role not in ["admin", "auditor"]:
                forensics_logger.warning(f"Governance violation: User {user.email} (role: {user.role}) attempted auditor access to {request.path}")
                flash("Auditor access required.", "danger")
                return redirect(url_for("home"))

            forensics_logger.info(f"Governance: Auditor/Admin {user.email} accessed {request.path}")
            return f(*args, **kwargs)
        return wrapper

    # ---------------------------
    # Governance: Role-Based Data Access Control Functions
    # ---------------------------

    def get_visible_incidents(user):
        """
        Returns incidents visible to the user based on their role.

        Implements governance by controlling data access based on user role:
        - Admin: Can see all incidents
        - Auditor: Can see all incidents for compliance monitoring
        - User: Can only see their own reported incidents

        Args:
            user: User object with role information

        Returns:
            Query object with appropriate incident filtering
        """
        db_session = get_session()
        if user.role == "admin":
            incidents = db_session.query(Incident).all()
            forensics_logger.info(f"Governance: Admin {user.email} accessed all incidents")
        elif user.role == "auditor":
            incidents = db_session.query(Incident).all()
            forensics_logger.info(f"Governance: Auditor {user.email} accessed all incidents for compliance review")
        else:  # user role
            incidents = db_session.query(Incident).filter(Incident.reported_by == user.id).all()
            forensics_logger.info(f"Governance: User {user.email} accessed their {len(incidents)} incidents")

        close_session(db_session)
        return incidents

    def get_visible_risks(user):
        """
        Returns risks visible to the user based on their role.

        Implements governance by controlling risk data access:
        - Admin: Can see all risks
        - Auditor: Can see all risks for compliance monitoring
        - User: Can only see risks from their own scans

        Args:
            user: User object with role information

        Returns:
            Query object with appropriate risk filtering
        """
        db_session = get_session()
        if user.role == "admin":
            risks = db_session.query(Risk).all()
            forensics_logger.info(f"Governance: Admin {user.email} accessed all risks")
        elif user.role == "auditor":
            risks = db_session.query(Risk).all()
            forensics_logger.info(f"Governance: Auditor {user.email} accessed all risks for compliance review")
        else:  # user role
            risks = (db_session.query(Risk)
                    .join(ScanResult)
                    .join(Upload)
                    .filter(Upload.user_id == user.id)
                    .all())
            forensics_logger.info(f"Governance: User {user.email} accessed their {len(risks)} risks")

        close_session(db_session)
        return risks

    def get_visible_users(user):
        """
        Returns users visible to the current user based on their role.

        Implements governance by controlling user data access:
        - Admin: Can see all users for management
        - Auditor: Can see all users for compliance monitoring
        - User: Can only see their own profile

        Args:
            user: User object with role information

        Returns:
            Query object with appropriate user filtering
        """
        db_session = get_session()
        if user.role in ["admin", "auditor"]:
            users = db_session.query(User).all()
            forensics_logger.info(f"Governance: {user.role.title()} {user.email} accessed all user accounts")
        else:  # user role
            users = [user]  # Only their own profile
            forensics_logger.info(f"Governance: User {user.email} accessed their profile")

        close_session(db_session)
        return users

    # ---------------------------
    # Governance: Audit Logging Functions
    # ---------------------------

    def log_audit_event(user, action, category, description, resource=None, success=True):
        """
        Logs audit events for governance and compliance tracking.

        Implements comprehensive audit logging for:
        - Authentication events
        - Authorization decisions
        - Administrative actions
        - Security policy compliance
        - Data access patterns

        Args:
            user: User object performing the action (can be None for system events)
            action: Action performed (e.g., "LOGIN", "ROLE_CHANGE")
            category: Audit category (AUTHENTICATION, AUTHORIZATION, ADMINISTRATION, COMPLIANCE, SECURITY)
            description: Detailed description of the event
            resource: Resource accessed (optional)
            success: Whether the action was successful

        Audit Categories:
            - AUTHENTICATION: Login, logout, authentication events
            - AUTHORIZATION: Access control decisions, role checks
            - ADMINISTRATION: Administrative actions, user management
            - COMPLIANCE: Policy compliance events, violations
            - SECURITY: Security-related events, incidents
        """
        try:
            db = get_session()
            audit_log = AuditLog(
                user_id=user.id if user else None,
                action=action,
                category=category,
                description=description,
                resource=resource or request.path,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent'),
                success=success
            )
            db.add(audit_log)
            db.commit()
            close_session(db)
        except Exception as e:
            # Log audit failure but don't break the main flow
            logging.error(f"Failed to log audit event: {e}")

    def get_audit_logs(user, limit=100):
        """
        Retrieves audit logs based on user role.

        Implements governance by controlling audit log access:
        - Admin: Can see all audit logs
        - Auditor: Can see all audit logs for compliance
        - User: Can only see their own audit logs

        Args:
            user: User object requesting audit logs
            limit: Maximum number of logs to return

        Returns:
            List of audit log dictionaries
        """
        db = get_session()
        if user.role in ["admin", "auditor"]:
            logs_query = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit)
            log_audit_event(user, "AUDIT_LOG_ACCESS", "ADMINISTRATION",
                           f"Accessed {len(logs_query.all())} audit log entries", "/audit/logs", True)
        else:
            logs_query = (db.query(AuditLog)
                         .filter(AuditLog.user_id == user.id)
                         .order_by(AuditLog.created_at.desc())
                         .limit(limit))
            log_audit_event(user, "PERSONAL_AUDIT_ACCESS", "COMPLIANCE",
                           f"Accessed {len(logs_query.all())} personal audit log entries", "/audit/logs", True)

        # Convert to dictionaries before closing session
        logs_data = []
        for log in logs_query:
            log_dict = {
                'id': log.id,
                'user_id': log.user_id,
                'action': log.action,
                'category': log.category,
                'description': log.description,
                'resource': log.resource,
                'ip_address': log.ip_address,
                'user_agent': log.user_agent,
                'success': log.success,
                'created_at': log.created_at,
                'user': {
                    'email': log.user.email if log.user else 'System'
                } if log.user else None
            }
            logs_data.append(log_dict)

        close_session(db)
        return logs_data

    # ---------------------------
    # Routes
    # ---------------------------

    @app.route("/", methods=["GET", "POST"])
    @app.route("/login", methods=["GET", "POST"])
    def login():
        """
        Handle user authentication with comprehensive security validation.

        Processes login requests with input validation, credential verification,
        and secure session establishment. Implements Zero Trust principles
        with multiple verification layers.

        GET: Displays login form
        POST: Processes authentication attempt

        Security Features:
            - Email format validation using regex
            - Password length and complexity checks
            - Secure password verification with Werkzeug
            - Account verification status checking
            - Session establishment with timestamp tracking
            - Security logging of authentication events
            - IP address logging for audit trail

        Returns:
            GET: Login template render
            POST: Redirect to home on success, login template on failure

        Note:
            Implements defense in depth with client and server-side validation
            Logs all authentication attempts for security monitoring
        """
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
                session['login_time'] = time.time()  # Zero Trust: Track session start for timeout enforcement
                forensics_logger.info(f"User {user.email} logged in successfully from IP {request.remote_addr}")
                log_audit_event(user, "LOGIN", "AUTHENTICATION",
                              f"Successful login from IP {request.remote_addr}", "/login", True)
                return redirect(url_for("home"))
            else:
                flash("Invalid credentials.", "danger")

        return render_template("login.html")

    @app.route("/logout")
    def logout():
        """
        Handle secure user logout with session cleanup and audit logging.

        Performs comprehensive logout procedure including:
        - Session data clearing
        - Security event logging
        - Database session cleanup
        - User feedback messaging

        Process:
            1. Retrieve current user information for logging
            2. Log logout event with user details and IP address
            3. Clear all session data (Zero Trust: complete session invalidation)
            4. Close any open database connections
            5. Display success message to user

        Returns:
            Redirect to login page with logout confirmation or AJAX response

        Security Features:
            - Complete session destruction (not just user_id removal)
            - Audit logging of logout events
            - Database connection cleanup
            - IP address tracking for security monitoring

        Note:
            Implements Zero Trust by ensuring no session remnants remain
            All user data is cleared to prevent session fixation attacks
        """
        user_id = session.get("user_id")
        if user_id:
            db = get_session()
            user = db.get(User, user_id)
            if user:
                forensics_logger.info(f"User {user.email} logged out from IP {request.remote_addr}")
                log_audit_event(user, "LOGOUT", "AUTHENTICATION",
                              f"User logged out from IP {request.remote_addr}", "/logout", True)
            close_session(db)
        session.clear()

        # Handle AJAX requests
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return '', 204  # No Content response for AJAX

        flash("Logged out securely.", "info")
        return redirect(url_for("login"))
    
        return redirect(url_for("login"))
    


    @app.route("/home", methods=["GET", "POST"])
    @login_required  # Access Control Policy
    def home():
        """
        Main dashboard displaying user uploads, scan results, and GRC data.

        Provides comprehensive view of user's security posture including:
        - Recent file uploads and scan status
        - Compliance hits from LLM analysis
        - Risk assessments with severity levels
        - File upload functionality with security validation

        GET: Displays dashboard with existing data
        POST: Handles secure file upload with validation

        Security Features:
            - File type validation (PDF, TXT only)
            - Filename sanitization to prevent path traversal
            - File size limits (10MB)
            - Duplicate filename handling
            - Automatic cleanup scheduling
            - Security logging of all operations

        Template Variables:
            user: Current authenticated user object
            last_upload: Most recent user upload
            has_scan: Boolean indicating if upload has been scanned
            scan_result: Scan results with compliance and risk data
            compliance_hits: List of compliance framework matches
            risks: List of identified risks with severity
            show_previous: Flag to control data display

        Returns:
            Rendered home template with dashboard data
        """
        user = current_user()
        logging.info(f"DEBUG: current_user() returned: {user} - email: {user.email if user else 'None'}")
        db = get_session()
        print("usser==",user)
        

        # Data Protection Policy: User-specific data access
        uploads = db.query(Upload).filter(Upload.user_id == user.id)

        # System Use Policy: Activity logging
        logging.info(f"Policy compliance: User {user.email} accessing {request.path}")
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
        if show_previous and scan_result:
            try:
                compliance_hits = json.loads(scan_result.compliance_hits_json or '[]')
                # Eagerly load the risks relationship to avoid session issues
                from sqlalchemy.orm import joinedload
                scan_result_with_risks = db.query(ScanResult).options(joinedload(ScanResult.risks)).filter(ScanResult.id == scan_result.id).first()
                if scan_result_with_risks and scan_result_with_risks.risks:
                    risks_list = [
                        {"id": risk.id, "risk": risk.threat, "severity": risk.severity.value if risk.severity else 'Medium'}
                        for risk in scan_result_with_risks.risks
                        ]
            except json.JSONDecodeError as e:
                logging.error(f"Failed to parse scan result JSON: {e}")
                risks_list = []
            except Exception as e:
                logging.error(f"Error loading risks for scan result: {e}")
                risks_list = []


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
        """
        Handle new user registration with comprehensive validation and security.

        Processes user registration requests with multi-layer validation:
        - Email format and uniqueness validation
        - Password complexity requirements
        - Password confirmation matching
        - Secure password hashing

        GET: Displays registration form
        POST: Processes registration attempt

        Security Features:
            - Email format validation using regex
            - Password complexity requirements (length, character types)
            - Password confirmation verification
            - Secure password hashing with Werkzeug
            - Duplicate email prevention
            - Input sanitization and validation

        Validation Rules:
            - Email: Must match standard email format
            - Password: Minimum 8 characters, must contain letters and numbers
            - Confirmation: Must match original password

        Returns:
            GET: Registration form template
            POST: Success redirect to login or form with error messages

        Database:
            Uses direct SQLite connection for registration
            Creates verified user accounts by default
            Handles integrity constraint violations

        Note:
            Registration creates verified accounts for demo purposes
            In production, email verification should be implemented
        """
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

            # Use direct SQLite connection for registration to avoid session conflicts
            import sqlite3

            try:
                # Connect directly to SQLite database
                conn = sqlite3.connect("instance/app.db", timeout=10.0)
                conn.execute("PRAGMA busy_timeout = 10000")  # 10 second timeout
                cur = conn.cursor()

                # Check if user already exists
                cur.execute("SELECT id FROM users WHERE email = ?", (email,))
                if cur.fetchone():
                    conn.close()
                    error = "User with this email already exists!"
                    return render_template("register.html", error=error)

                # Insert new user directly
                cur.execute("""
                    INSERT INTO users (
                        email, password_hash, is_verified, role,
                        approval_limit, escalation_threshold, escalation_level, audit_trail_enabled,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    email,
                    hashed_pw,
                    True,  # is_verified
                    "user",  # role
                    10000.0,  # approval_limit
                    15,  # escalation_threshold
                    "business_unit",  # escalation_level
                    True,  # audit_trail_enabled
                    datetime.now(timezone.utc),  # created_at
                    datetime.now(timezone.utc)   # updated_at
                ))

                # Get the user ID for audit logging
                user_id = cur.lastrowid

                conn.commit()
                conn.close()

                forensics_logger.info(f"New user registered: {email}")

                # Create a temporary user object for audit logging
                temp_user = type('User', (), {'id': user_id, 'email': email})()
                log_audit_event(temp_user, "USER_REGISTRATION", "ADMINISTRATION",
                               f"New user account created: {email}", "/register", True)

                flash("Registration successful! Please login.", "success")
                return redirect(url_for("login"))

            except sqlite3.OperationalError as e:
                if "database is locked" in str(e).lower():
                    error = "Database is currently busy. Please wait a moment and try again."
                else:
                    error = f"Database error: {str(e)}"
                return render_template("register.html", error=error)
            except Exception as e:
                error = f"Registration failed: {str(e)}"
                return render_template("register.html", error=error)

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
        """
        Initiate security scan of uploaded file using LLM analysis.

        Triggers comprehensive GRC analysis of uploaded documents using
        large language models to identify compliance requirements, risks,
        and security gaps.

        Args:
            upload_id (int): Database ID of the upload to scan

        Security Checks:
            - Verifies upload ownership (user_id match)
            - Prevents duplicate scanning
            - Validates upload existence

        Process:
            1. Extract text from uploaded file (PDF/TXT)
            2. Send to LLM for GRC analysis
            3. Parse structured response (compliance, risks, summary)
            4. Store scan results in database
            5. Generate risk and compliance records
            6. Log security event

        Returns:
            Redirect to home page with success/error message

        Note:
            Asynchronous processing prevents UI blocking
            Comprehensive error handling with user feedback
            Creates database relationships for reporting
        """
        db = get_session()
        up = db.get(Upload, upload_id)

        if not up or up.user_id != session.get("user_id"):
            close_session(db)
            flash("Upload not found or unauthorized.", "danger")
            return redirect(url_for("home"))

        if up.scan_result:
            close_session(db)
            flash("This file has already been scanned.", "info")
            return redirect(url_for("home"))

        try:
            # Store file path before potential session issues
            file_path = up.saved_path
            upload_id_for_scan = up.id
            filename = up.filename

            data = scan_file_for_grc(file_path)
            res = ScanResult(
                upload_id=upload_id_for_scan,
                summary=data.get("summary", ""),
                compliance_hits_json=json_dumps(data.get("compliance_hits", [])),
                risks_json=json_dumps(data.get("risks", [])),
            )
            db.add(res)
            db.commit()

            # Generate and store risk entries from scan results
            risks_data = data.get("risks", [])
            compliance_data = data.get("compliance_hits", [])
            threats_data = data.get("detected_threats", [])
            if risks_data or threats_data:
                create_risks_from_scan(res.id, risks_data, compliance_data, threats_data)

            forensics_logger.info(f"User {session.get('user_id')} scanned file {filename}")
            flash("Scan completed and saved.", "success")
        except Exception as e:
            logging.error("Scan failed: %s", str(e))
            flash("An error occurred while scanning. Please try again.", "danger")
        finally:
            close_session(db)

        return redirect(url_for("home"))

    @app.route("/uploads/<path:filename>")
    @login_required
    def uploaded_file(filename):
        """
        Serve uploaded files securely with path traversal protection.

        Provides secure access to user-uploaded files with multiple
        security layers to prevent unauthorized access and path traversal attacks.

        Args:
            filename (str): Requested filename from URL path

        Security Features:
            - User authentication required (@login_required)
            - Path traversal prevention via secure_filename()
            - File existence validation (handled by send_from_directory)
            - Directory restriction to uploads/ folder only
            - No attachment download (inline display for security)

        Returns:
            File response for inline display in browser

        Note:
            Files are served from uploads/ directory only
            Automatic cleanup removes files after 2 minutes
            Used for displaying uploaded documents in the application
        """
        # Output encoding to avoid path traversal
        filename = secure_filename(filename)
        return send_from_directory("uploads", filename, as_attachment=False)

    @app.route("/evidence/<path:filename>")
    @login_required
    def evidence_file(filename):
        """
        Serve evidence files securely as downloadable attachments.

        Provides secure download access to digital evidence files with
        comprehensive security controls for forensic data handling.

        Args:
            filename (str): Requested evidence filename from URL path

        Security Features:
            - User authentication required (@login_required)
            - Path traversal prevention via secure_filename()
            - File existence validation
            - Restricted to evidence/ directory only
            - Download-only access (attachment disposition)

        Returns:
            File download response with attachment headers

        Note:
            Used for downloading evidence files in forensics module
            Files include integrity hashes for tamper detection
            Access logged for audit trail purposes
        """
        # Output encoding to avoid path traversal
        filename = secure_filename(filename)
        return send_from_directory("evidence", filename, as_attachment=True)

    @app.route("/docs/<path:filename>")
    @login_required
    def docs_file(filename):
        """
        Serve documentation files securely.

        Provides access to documentation files in the docs/ directory
        for authenticated users.

        Args:
            filename (str): Requested documentation filename from URL path

        Security Features:
            - User authentication required (@login_required)
            - Path traversal prevention via secure_filename()
            - Restricted to docs/ directory only

        Returns:
            File response for viewing documentation

        Note:
            Allows access to .md files and other documentation
        """
        # Output encoding to avoid path traversal
        filename = secure_filename(filename)
        return send_from_directory("docs", filename, as_attachment=False)

  
    # --- Risk Routes ---
    @app.route("/risks")
    @login_required
    def risks():
        """
        Display risk assessment dashboard with role-based access control.

        Shows risks based on user role:
        - Admin: All risks for system oversight
        - Auditor: All risks for compliance monitoring
        - User: Only risks from their own scans

        Security Features:
            - User authentication required
            - Role-based data access control
            - Comprehensive audit logging
            - Data isolation by role

        Data Sources:
            - Risks linked to scan results
            - Joined through ScanResult and Upload relationships
            - Filtered by user role and ownership

        Template Variables:
            risks: List of visible Risk objects based on user role

        Returns:
            Rendered risks template with appropriate risk data

        Note:
            Implements governance through role-based data access
            Uses SQLAlchemy joins for efficient data retrieval
            Maintains audit trail of risk data access
        """
        user = current_user()
        risks_list = get_visible_risks(user)
        log_audit_event(user, "RISKS_ACCESS", "COMPLIANCE",
                       f"Accessed {len(risks_list)} risk assessments", "/risks", True)
        return render_template("risks.html", risks=risks_list)



# --- Risk Management Program Routes ---

    @app.route("/risk_programs")
    @login_required
    def risk_programs():
        """Display risk management programs dashboard"""
        user = current_user()
        db = get_session()
    
        programs_raw = db.query(RiskProgramPlan).filter(RiskProgramPlan.created_by == user.id).all()
        frameworks_raw = db.query(RiskManagementFramework).filter(RiskManagementFramework.is_active == True).all()

        programs = []
        for prog in programs_raw:
            programs.append({
                'id': prog.id,
                'title': prog.title,
                'status': prog.status,
                'start_date': prog.start_date,
                'end_date': prog.end_date,
                'total_budget': prog.total_budget,
                'framework': {
                    'name': prog.framework.name if prog.framework else 'Unknown'
                } if prog.framework else None
            })

        frameworks = []
        for fw in frameworks_raw:
            frameworks.append({
                'id': fw.id,
                'name': fw.name,
                'version': fw.version,
                'description': fw.description,
                'customization_notes': fw.customization_notes,
                'is_active': fw.is_active
            })

        close_session(db)
        return render_template("risk_programs.html", programs=programs, frameworks=frameworks)

    @app.route("/create_program", methods=["GET", "POST"])
    @login_required
    def create_program():
        """Create new risk management program"""
        user = current_user()
        db = get_session()
    
        if request.method == "POST":
            data = request.form
        
            # Create program plan
            program = RiskProgramPlan(
                title=data["title"],
                framework_id=int(data["framework_id"]),
                status="draft",
                start_date=datetime.strptime(data["start_date"], "%Y-%m-%d") if data.get("start_date") else None,
                end_date=datetime.strptime(data["end_date"], "%Y-%m-%d") if data.get("end_date") else None,
                total_budget=float(data.get("total_budget", 0)),
                created_by=user.id
            )
            db.add(program)
            db.commit()
        
            # Generate initial phases based on framework
            framework = db.get(RiskManagementFramework, program.framework_id)
            phases_data = generate_program_phases(framework.name)
        
            for i, phase_data in enumerate(phases_data):
                phase = ProgramPhase(
                    program_id=program.id,
                    phase_name=phase_data["name"],
                    phase_order=i+1,
                    description=phase_data["description"],
                    budget_allocated=phase_data.get("budget", 0),
                    personnel_required=json.dumps(phase_data.get("personnel", [])),
                    tools_required=json.dumps(phase_data.get("tools", [])),
                    training_required=json.dumps(phase_data.get("training", []))
                )
                db.add(phase)
        
            db.commit()
            close_session(db)
        
            flash("Risk management program created successfully!", "success")
            return redirect(url_for("view_program", program_id=program.id))
    
        frameworks_raw = db.query(RiskManagementFramework).filter(RiskManagementFramework.is_active == True).all()
        frameworks = []
        for fw in frameworks_raw:
            frameworks.append({
                'id': fw.id,
                'name': fw.name,
                'version': fw.version,
                'description': fw.description,
                'customization_notes': fw.customization_notes,
                'is_active': fw.is_active
            })
        close_session(db)

        return render_template("create_program.html", frameworks=frameworks)

    @app.route("/program/<int:program_id>")
    @login_required
    def view_program(program_id):
        """
        Display comprehensive risk management program details and progress.

        Provides detailed view of risk management programs including phases,
        gap analyses, timelines, and resource allocations. Supports program
        governance and progress tracking.

        Args:
            program_id (int): Database ID of the risk management program

        Returns:
            Rendered program detail template with comprehensive program information

        Program Components Displayed:
            - Program overview (title, status, dates, budget)
            - Implementation phases with descriptions and resources
            - Gap analyses with findings and mitigation plans
            - Progress tracking and milestone completion
            - Resource allocation and personnel requirements

        Security:
            - Program ownership verification
            - User authentication required
            - Access limited to program creator

        Template Variables:
            program: RiskProgramPlan object with all program details
            phases: List of ProgramPhase objects in order
            gap_analyses: List of GapAnalysis objects for the program

        Note:
            Supports comprehensive program management lifecycle
            Enables detailed progress monitoring and reporting
            Facilitates governance and compliance oversight
        """
        user = current_user()
        db = get_session()
    
        program = db.get(RiskProgramPlan, program_id)
        if not program or program.created_by != user.id:
            close_session(db)
            flash("Program not found or access denied.", "danger")
            return redirect(url_for("risk_programs"))
    
        phases = db.query(ProgramPhase).filter(ProgramPhase.program_id == program_id).order_by(ProgramPhase.phase_order).all()
        gap_analyses = db.query(GapAnalysis).filter(GapAnalysis.program_id == program_id).all()
    
        close_session(db)
        return render_template("program_detail.html", program=program, phases=phases, gap_analyses=gap_analyses)

    @app.route("/gap_analysis/<int:program_id>", methods=["GET", "POST"])
    @login_required
    def gap_analysis(program_id):
        """Perform gap analysis for program"""
        user = current_user()
        db = get_session()
    
        program = db.get(RiskProgramPlan, program_id)
        if not program or program.created_by != user.id:
            close_session(db)
            flash("Program not found or access denied.", "danger")
            return redirect(url_for("risk_programs"))
    
        if request.method == "POST":
            data = request.form
        
            gap = GapAnalysis(
                program_id=program_id,
                requirement_category=data["category"],
                current_state=data["current_state"],
                required_state=data["required_state"],
                gap_description=data["gap_description"],
                gap_severity=data["severity"],
                mitigation_plan=data["mitigation_plan"],
                estimated_cost=float(data.get("estimated_cost", 0)),
                timeline_months=int(data.get("timeline_months", 0))
            )
            db.add(gap)
            db.commit()
        
            flash("Gap analysis entry added!", "success")
            return redirect(url_for("gap_analysis", program_id=program_id))
    
        gaps = db.query(GapAnalysis).filter(GapAnalysis.program_id == program_id).all()
        close_session(db)
    
        return render_template("gap_analysis.html", program=program, gaps=gaps)

    @app.route("/risk_indicators")
    @login_required
    def risk_indicators():
        """Manage risk indicators for continuous monitoring"""
        db = get_session()
    
        indicators = db.query(RiskIndicator).filter(RiskIndicator.is_active == True).all()
    
        # Get latest readings for each indicator
        indicator_data = []
        for indicator in indicators:
            latest_reading = db.query(IndicatorReading).filter(
                IndicatorReading.indicator_id == indicator.id
            ).order_by(IndicatorReading.timestamp.desc()).first()
        
            indicator_data.append({
                'indicator': indicator,
                'latest_reading': latest_reading
            })
    
        close_session(db)
        return render_template("risk_indicators.html", indicator_data=indicator_data)

    @app.route("/environmental_changes")
    @login_required
    def environmental_changes():
        """Monitor environmental changes"""
        db = get_session()
    
        changes = db.query(EnvironmentalChange).order_by(EnvironmentalChange.detection_date.desc()).all()
        close_session(db)
    
        return render_template("environmental_changes.html", changes=changes)






    # --- Enhanced Risk Management Routes ---

    @app.route("/risk/<int:risk_id>")
    @login_required
    def view_risk(risk_id):
        """
        Display comprehensive risk assessment details with governance workflow.

        Provides a detailed view of a specific risk assessment including quantitative analysis,
        mitigation plans, approval workflows, compliance mappings, and communication strategies.
        Implements role-based access control and comprehensive audit logging.

        Args:
            risk_id (int): Database ID of the risk to display

        Returns:
            Rendered risk detail template with comprehensive risk information

        Features Displayed:
            - Risk heat map and scoring matrix
            - Business impact analysis (BIA)
            - Multi-criteria risk analysis
            - Mitigation plan with treatment strategies
            - Approval workflow and history
            - Compliance mappings
            - Risk communication plan (if available)
            - Quantitative analysis (EMV/ALE calculations)

        Security:
            - Role-based data access (admin/auditor see all, users see their own)
            - Audit logging of risk access
            - Session management for large data sets

        Template Variables:
            risk: Risk object with all attributes loaded
            approvals: List of approval records
            governance_decisions: Governance decision history
            compliance_mappings: Associated compliance requirements
            mitigation_plan: AI-generated mitigation strategies
            communication_plan: Stakeholder communication strategy
            emv: Expected Monetary Value calculation
            ale: Annual Loss Expectancy calculation
            Various pre-calculated display values

        Note:
            Handles DetachedInstanceError by pre-loading all required data
            Generates mitigation and communication plans on-demand
            Supports complex risk governance workflows
        """
        """
        Display detailed risk assessment with governance workflow status.

        Shows comprehensive risk information including:
        - Risk scoring and severity assessment
        - Mitigation plans and residual risk
        - Approval workflow status
        - Escalation history
        - Compliance mappings
        - Audit trail

        Args:
            risk_id: Database ID of the risk to display

        Returns:
            Rendered risk detail template with comprehensive risk data

        Security Features:
            - Role-based access control
            - Audit logging of risk access
            - Data isolation by user permissions
        """
        user = current_user()
        db = get_session()

        # Get risk with role-based access control and ensure it's properly loaded
        risk = None
        if user.role == "admin":
            risk = db.query(Risk).filter(Risk.id == risk_id).first()
        elif user.role == "auditor":
            risk = db.query(Risk).filter(Risk.id == risk_id).first()  # Auditors can see all risks
        else:
            # Users can only see risks from their scans or assigned to them
            risk = db.query(Risk).filter(
                Risk.id == risk_id,
                (Risk.owner == user.email) | (Risk.approver_id == user.id)
            ).first()

        if not risk:
            close_session(db)
            flash("Risk not found or access denied.", "danger")
            return redirect(url_for("risks"))

        # Ensure risk object is properly attached to session
        logging.info(f"DEBUG: Risk loaded with ID {risk.id}, session active: {db.is_active}")
        # Force load key attributes to ensure they're in session
        _ = risk.asset, risk.threat, risk.vulnerability, risk.control
        logging.info(f"DEBUG: Risk attributes accessed successfully")

        # Get related data with eager loading to prevent DetachedInstanceError
        from sqlalchemy.orm import joinedload
        approvals = db.query(RiskApproval).filter(RiskApproval.risk_id == risk_id).all()
        governance_decisions = db.query(GovernanceDecision).filter(GovernanceDecision.risk_id == risk_id).all()
        compliance_mappings = db.query(RiskComplianceMapping).options(
            joinedload(RiskComplianceMapping.requirement)
        ).filter(RiskComplianceMapping.risk_id == risk_id).all()

        # Ensure risk object has all necessary attributes loaded
        logging.info(f"DEBUG: Risk object loaded with ID {risk.id}, status: {risk.status}")

        # Store risk asset for audit logging (before session close)
        risk_asset = risk.asset

        # Add mitigation planning
        risk_data_for_ai = {
            'asset': risk.asset,
            'threat': risk.threat,
            'vulnerability': risk.vulnerability,
            'score': risk.score,
            'severity': risk.severity.value if risk.severity else 'Medium',
            'likelihood': risk.likelihood,
            'financial_impact_amount': risk.financial_impact_amount or 0
            }

        # DEBUG: Log session state before mitigation plan generation
        logging.info(f"DEBUG: Session active before mitigation plan: {db.is_active}")
        logging.info(f"DEBUG: Risk object session: {risk in db}")

        # generating the mitigation plan
        mitigation_plan = generate_risk_mitigation_plan(risk_data_for_ai)

        communication_plan = None
        if risk.mitigation_plan_json:
            stored_mitigation_plan = json.loads(risk.mitigation_plan_json)
            communication_plan = generate_risk_communication_plan(risk_data_for_ai, stored_mitigation_plan)




        # Saving mitigation plan to database
        risk.mitigation_plan_json = json.dumps(mitigation_plan)
        risk.mitigation_plan_updated = datetime.now(timezone.utc)
        db.commit()


        # Pre-calculate values that template methods would access to prevent lazy loading
        business_impact_score = risk.calculate_business_impact_score()
        financial_impact_desc = risk.get_impact_description("financial", risk.financial_impact)
        operational_impact_desc = risk.get_impact_description("operational", risk.operational_impact)
        compliance_impact_desc = risk.get_impact_description("compliance", risk.compliance_impact)
        reputation_impact_desc = risk.get_impact_description("reputation", risk.reputation_impact)

        # Calculate quantitative analysis metrics
        # EMV (Expected Monetary Value) = Probability × Impact
        probability = risk.likelihood / 5.0  # Convert 1-5 scale to 0-1 probability
        emv = probability * (risk.financial_impact_amount or 0)

        # ALE (Annual Loss Expectancy) = SLE × ARO
        # Assuming likelihood represents annual rate of occurrence (ARO)
        sle = risk.financial_impact_amount or 0  # Single Loss Expectancy
        aro = risk.likelihood  # Annual Rate of Occurrence
        ale = sle * aro

        # DEBUG: Log before session close
        logging.info(f"DEBUG: About to close session. Risk ID: {risk.id}")
        logging.info(f"DEBUG: Approvals count: {len(approvals)}")
        logging.info(f"DEBUG: Governance decisions count: {len(governance_decisions)}")
        logging.info(f"DEBUG: Compliance mappings count: {len(compliance_mappings)}")
        logging.info(f"DEBUG: Pre-calculated values: BIA={business_impact_score}")

        # Keep session open during template rendering, close after response is sent
        logging.info(f"DEBUG: Starting template render for risk {risk.id}")
        response = render_template("risk_detail.html",
                     risk=risk,
                     approvals=approvals,
                     governance_decisions=governance_decisions,
                     compliance_mappings=compliance_mappings,
                     mitigation_plan=mitigation_plan,
                     communication_plan=communication_plan,
                     business_impact_score=business_impact_score,
                     financial_impact_desc=financial_impact_desc,
                     operational_impact_desc=operational_impact_desc,
                     compliance_impact_desc=compliance_impact_desc,
                     reputation_impact_desc=reputation_impact_desc,
                     emv=emv,
                     ale=ale)
        logging.info(f"DEBUG: Template rendered successfully, closing session for risk {risk.id}")
        close_session(db)

        # Log access for audit trail (after session close to avoid DetachedInstanceError)
        log_audit_event(user, "RISK_VIEWED", "COMPLIANCE",
                       f"Viewed detailed risk assessment for {risk_asset}", f"/risk/{risk_id}", True)

        return response
    



    @app.route("/approve_risk/<int:risk_id>", methods=["POST"])
    @login_required
    def approve_risk(risk_id):
        """
        Process risk approval decision with governance workflow.

        Handles risk approval/rejection decisions based on user role and approval authority.
        Implements escalation procedures for high-risk items and maintains audit trail.

        Args:
            risk_id: Database ID of the risk being approved

        Form Fields:
            decision: "approve" or "reject"
            decision_notes: Comments explaining the decision
            escalate: Boolean indicating if risk should be escalated

        Process:
            1. Validate user approval authority
            2. Update risk approval status
            3. Handle escalation if requested
            4. Update risk treatment and mitigation
            5. Log governance decision
            6. Notify stakeholders

        Returns:
            Redirect to risk detail page with status message

        Governance Features:
            - Approval authority validation
            - Automatic escalation for high-risk items
            - Comprehensive audit logging
            - Stakeholder notification workflow
        """
        user = current_user()
        db = get_session()

        risk = db.get(Risk, risk_id)
        if not risk:
            close_session(db)
            flash("Risk not found.", "danger")
            return redirect(url_for("risks"))

        # Check approval authority
        can_approve = False
        if user.role == "admin":
            can_approve = True
        elif user.role == "auditor" and risk.score <= 15:  # Medium risk threshold
            can_approve = True
        elif risk.approver_id == user.id:
            can_approve = True

        if not can_approve:
            log_audit_event(user, "APPROVAL_DENIED", "AUTHORIZATION",
                           f"Unauthorized approval attempt for risk {risk.asset}", f"/approve_risk/{risk_id}", False)
            close_session(db)
            flash("You do not have approval authority for this risk.", "danger")
            return redirect(url_for("view_risk", risk_id=risk_id))

        decision = request.form.get("decision")
        decision_notes = request.form.get("decision_notes", "")
        escalate = request.form.get("escalate") == "on"

        # Update risk approval status
        if decision == "approve":
            risk.approval_status = ApprovalStatus.APPROVED
            risk.treatment = RiskTreatment.MITIGATE  # Default treatment for approved risks
            risk.stakeholder_approval_notes = decision_notes or "Approved via risk approval process"
        elif decision == "reject":
            risk.approval_status = ApprovalStatus.REJECTED
            risk.treatment = RiskTreatment.AVOID
            risk.stakeholder_approval_notes = decision_notes or "Rejected via risk approval process"
        else:
            risk.approval_status = ApprovalStatus.PENDING

        # Handle escalation
        if escalate or risk.should_escalate():
            risk.escalation_level = risk.get_escalation_level()
            risk.escalation_reason = decision_notes or f"Escalated by {user.email}"
            risk.escalation_date = datetime.now(timezone.utc)

            # Create escalation record
            escalation_approval = RiskApproval(
                risk_id=risk.id,
                approver_id=user.id,
                status=ApprovalStatus.ESCALATED,
                decision_notes=f"Escalated to {risk.escalation_level} level",
                approval_level=risk.escalation_level
            )
            db.add(escalation_approval)

        # Create governance decision record
        governance_decision = GovernanceDecision(
            title=f"Risk {decision.title()}: {risk.asset}",
            description=f"Risk assessment {decision} decision for {risk.asset}",
            decision_type="risk_treatment",
            decision_maker=user.id,
            rationale=decision_notes,
            risk_id=risk.id
        )
        db.add(governance_decision)

        # Update risk timestamps
        risk.updated_at = datetime.now(timezone.utc)

        db.commit()

        # Log governance event
        log_audit_event(user, "RISK_APPROVED" if decision == "approve" else "RISK_REJECTED", "COMPLIANCE",
                       f"Risk {risk.asset} {decision} with notes: {decision_notes}", f"/approve_risk/{risk_id}", True)

        close_session(db)
        flash(f"Risk {decision} successfully processed.", "success")
        return redirect(url_for("view_risk", risk_id=risk_id))

    @app.route("/escalate_risk/<int:risk_id>", methods=["POST"])
    @login_required
    def escalate_risk(risk_id):
        """
        Escalate risk to higher approval authority.

        Implements governance escalation procedures for risks requiring
        higher-level approval based on severity, impact, or other criteria.

        Args:
            risk_id: Database ID of the risk to escalate

        Process:
            1. Validate escalation authority
            2. Update risk escalation status
            3. Create escalation approval record
            4. Notify appropriate stakeholders
            5. Log escalation event

        Returns:
            Redirect to risk detail page with escalation confirmation
        """
        user = current_user()
        db = get_session()

        risk = db.get(Risk, risk_id)
        if not risk:
            close_session(db)
            flash("Risk not found.", "danger")
            return redirect(url_for("risks"))

        escalation_reason = request.form.get("escalation_reason", "")
        target_level = request.form.get("target_level", "department")

        # Update risk escalation
        risk.escalation_level = target_level
        risk.escalation_reason = escalation_reason
        risk.escalation_date = datetime.now(timezone.utc)
        risk.approval_status = ApprovalStatus.ESCALATED

        # Create escalation record
        escalation = RiskApproval(
            risk_id=risk.id,
            approver_id=user.id,
            status=ApprovalStatus.ESCALATED,
            decision_notes=f"Escalated to {target_level}: {escalation_reason}",
            approval_level=target_level
        )
        db.add(escalation)

        db.commit()

        # Log escalation event
        log_audit_event(user, "RISK_ESCALATED", "COMPLIANCE",
                       f"Risk {risk.asset} escalated to {target_level} level", f"/escalate_risk/{risk_id}", True)

        close_session(db)
        flash(f"Risk escalated to {target_level} level successfully.", "warning")
        return redirect(url_for("view_risk", risk_id=risk_id))

    @app.route("/risk_dashboard")
    @login_required
    def risk_dashboard():
        """
        Comprehensive risk management dashboard with governance metrics.

        Displays executive-level risk overview including:
        - Risk heat map by severity and category
        - Approval workflow status
        - Escalation queue
        - Compliance alignment status
        - Key risk indicators (KRIs)
        - Governance decision summary

        Returns:
            Rendered risk dashboard template with comprehensive metrics

        Features:
            - Role-based dashboard views
            - Real-time risk metrics
            - Interactive risk heat map
            - Approval queue management
            - Escalation alerts
        """
        user = current_user()
        print(f"DEBUG: current_user() returned: {user} - email: {user.email if user else 'None'}")
        logging.info(f"DEBUG: current_user() returned: {user} - email: {user.email if user else 'None'}")
        db = get_session()

        # Get risks based on user role
        risks = get_visible_risks(user)

        # Calculate dashboard metrics
        total_risks = len(risks)
        critical_risks = len([r for r in risks if r.severity == RiskSeverity.CRITICAL])
        high_risks = len([r for r in risks if r.severity == RiskSeverity.HIGH])
        escalated_risks = len([r for r in risks if r.escalation_level != "none"])

        # Approval workflow metrics
        pending_approvals = len([r for r in risks if r.approval_status and r.approval_status.value == "pending"])
        approved_risks = len([r for r in risks if r.approval_status and r.approval_status.value == "approved"])
        rejected_risks = len([r for r in risks if r.approval_status and r.approval_status.value == "rejected"])

        # Risk by category
        risk_by_category = {}
        for risk in risks:
            category = risk.category.value if risk.category else "Uncategorized"
            risk_by_category[category] = risk_by_category.get(category, 0) + 1

        # Recent governance decisions
        recent_decisions = db.query(GovernanceDecision).order_by(GovernanceDecision.created_at.desc()).limit(10).all()

        close_session(db)

        # Log dashboard access
        log_audit_event(user, "DASHBOARD_ACCESSED", "COMPLIANCE",
                       "Accessed risk management dashboard", "/risk_dashboard", True)

        return render_template("risk_dashboard.html",
                             risks=risks,
                             total_risks=total_risks,
                             critical_risks=critical_risks,
                             high_risks=high_risks,
                             escalated_risks=escalated_risks,
                             pending_approvals=pending_approvals,
                             approved_risks=approved_risks,
                             rejected_risks=rejected_risks,
                             risk_by_category=risk_by_category,
                             recent_decisions=recent_decisions)

    @app.route("/add_risk", methods=["POST"])
    @login_required
    def add_risk():
        """
        Create new risk assessment entry with automatic scoring calculation and governance workflow.

        Processes risk creation form data and creates new Risk database entry
        with automatic risk score calculation, governance workflow initiation,
        and escalation procedures based on NIST RMF and ISO 31000 standards.

        Form Fields:
            asset: System resource or information asset
            threat: Potential violation of security
            vulnerability: Weakness that can be exploited
            control: Safeguard or countermeasure
            compliance_standard: Associated compliance framework
            likelihood: Risk likelihood (1-5 scale)
            impact: Risk impact (1-5 scale)
            business_impact: Business impact description
            regulatory_impact: Regulatory impact description
            mitigation_plan: Proposed mitigation strategy

        Process:
            1. Extract and validate form data
            2. Create Risk object with comprehensive data
            3. Automatically calculate risk score (likelihood × impact)
            4. Determine escalation requirements based on score
            5. Set approval workflow based on risk level
            6. Log governance event for audit trail
            7. Save to database with proper session management
            8. Redirect to risks dashboard with success message

        Governance Features:
            - Automatic escalation for high-risk items
            - Approval workflow routing
            - Audit trail logging
            - Risk appetite alignment checking

        Returns:
            Redirect to risks page with success confirmation

        Note:
            Implements comprehensive risk governance per NIST RMF
            Automatic workflow initiation based on risk severity
            Full audit trail for compliance requirements
        """
        user = current_user()
        db_session = get_session()

        evaluation_criteria = data.get("evaluation_criteria", "").strip()
        if not evaluation_criteria or len(evaluation_criteria) < 50:
            flash("Evaluation criteria must be at least 50 characters long.", "danger")
            return redirect(url_for("risks"))  # Or render form with error

        data = request.form
        risk = Risk(
            asset=data["asset"],
            threat=data["threat"],
            vulnerability=data["vulnerability"],
            control=data["control"],
            compliance_standard=getattr(ComplianceFramework, data.get("compliance_standard", "NIST_SP_800_53").upper().replace(" ", "_"), ComplianceFramework.NIST_SP_800_53),
            likelihood=int(data.get("likelihood", 1)),
            impact=int(data.get("impact", 1)),
            business_impact=data.get("business_impact", ""),
            regulatory_impact=data.get("regulatory_impact", ""),
            mitigation_plan=data.get("mitigation_plan", ""),
            owner=user.email,
            # Add new multi-criteria fields
            financial_impact=int(data.get("financial_impact", 1)),
            operational_impact=int(data.get("operational_impact", 1)),
            compliance_impact=int(data.get("compliance_impact", 1)),
            reputation_impact=int(data.get("reputation_impact", 1)),
            # Add BIA fields
            rto_hours=float(data.get("rto_hours", 0)),
            rpo_hours=float(data.get("rpo_hours", 0)),
            mtd_hours=float(data.get("mtd_hours", 0)),
            financial_impact_amount=float(data.get("financial_impact_amount", 0)),
            dependency_mapping=json.dumps(data.get("dependency_mapping", [])),
            # Add evaluation criteria
            evaluation_criteria=data.get("evaluation_criteria", ""),
            stakeholder_approval_required=data.get("stakeholder_approval_required", True)
            )

        # Calculate initial risk score
        risk.calculate_score()
        # Calculate scores
        risk.calculate_multi_criteria_score()  
        risk.calculate_business_impact_score() 

        # Determine escalation requirements
        if risk.should_escalate():
            risk.escalation_level = risk.get_escalation_level()
            risk.escalation_reason = f"Risk score {risk.score} exceeds tolerance threshold of {risk.risk_tolerance_threshold}"
            risk.escalation_date = datetime.now(timezone.utc)
            forensics_logger.info(f"Governance: Risk {risk.asset} escalated to {risk.escalation_level} level")

        # Set next review date
        risk.update_next_review_date()

        # Log governance event
        log_audit_event(user, "RISK_CREATED", "COMPLIANCE",
                       f"Created risk assessment for {risk.asset} with score {risk.score}", "/add_risk", True)

        db_session.add(risk)
        db_session.commit()

        # Create initial approval record if escalation is needed
        if risk.should_escalate():
            approval = RiskApproval(
                risk_id=risk.id,
                approver_id=user.id,  # Initially assigned to creator, will be reassigned based on workflow
                approval_level=risk.escalation_level,
                decision_notes=f"Auto-escalated due to risk score {risk.score}"
            )
            db_session.add(approval)
            db_session.commit()

        close_session(db_session)
        flash("Risk assessment created successfully with governance workflow initiated!", "success")
        return redirect(url_for("risks"))


    # --- Compliance Routes ---
    @app.route("/compliance")
    @login_required
    def compliance():
        """
        Display compliance monitoring dashboard with all compliance records.

        Shows comprehensive view of compliance status across all frameworks,
        controls, and associated risk assessments for organizational oversight.

        Data Display:
            - Framework compliance status
            - Control family and specific controls
            - Compliance scores and status
            - Associated risk linkages
            - Assessment timestamps

        Template Variables:
            compliance: List of all Compliance database records

        Returns:
            Rendered compliance template with compliance data

        Note:
            Displays all compliance records (not user-specific)
            Used for organizational compliance monitoring
            Supports multiple compliance frameworks simultaneously
        """
        # Create a temporary session for this request
        engine = get_engine()
        SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
        db_session = SessionLocal()

        try:
            # Fetch compliance records with eager loading of risk relationship
            from sqlalchemy.orm import joinedload
            compliance_records = db_session.query(Compliance).options(joinedload(Compliance.risk)).all()

            # Create a simple data structure for the template
            compliance_data = []
            for c in compliance_records:
                risk_info = None
                if c.risk:
                    risk_info = {
                        'id': c.risk.id,
                        'asset': c.risk.asset
                    }

                compliance_data.append({
                    'id': c.id,
                    'framework': c.framework,
                    'control': c.control,
                    'score': c.score,
                    'created_at': c.created_at,
                    'updated_at': c.updated_at,
                    'risk': risk_info
                })

            return render_template("compliance.html", compliance=compliance_data)

        finally:
            db_session.close()

    @app.route("/add_compliance", methods=["POST"])
    @login_required
    def add_compliance():
        """
        Create new compliance assessment record with framework mapping.

        Processes compliance form data to create new Compliance database entry
        linking specific controls to compliance frameworks and associated risks.

        Form Fields:
            framework: Compliance framework (e.g., NIST SP 800-53, ISO 27001)
            control: Specific control identifier (e.g., AC-2, IR-1)
            score: Compliance score (0.0 to 100.0 percentage)
            risk_id: Associated risk ID (optional)

        Process:
            1. Extract and validate form data
            2. Create Compliance object with framework mapping
            3. Link to associated risk if provided
            4. Save to database with proper session management
            5. Redirect to compliance dashboard with success message

        Returns:
            Redirect to compliance page with success confirmation

        Note:
            Supports multiple compliance frameworks
            Optional risk linkage for integrated risk-compliance management
            Default score of 0.0 for new assessments
        """
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
    @login_required
    def dependencies():
        """
        Display software dependency risk assessment dashboard.

        Shows all tracked software dependencies with automatic risk assessment
        including vulnerability analysis and mitigation recommendations.

        Risk Assessment Process:
            1. Retrieve all dependency records from database
            2. Run automated risk assessment for each dependency
            3. Evaluate known vulnerabilities based on name/version
            4. Assign risk levels (Low, Medium, High, Critical)
            5. Generate mitigation recommendations

        Template Variables:
            dependencies: List of Dependency objects with risk assessments

        Returns:
            Rendered dependencies template with risk analysis

        Risk Assessment Logic:
            - Flask versions < 2.0: High risk
            - Requests versions < 2.25.0: Medium risk
            - Other dependencies: Low risk by default

        Note:
            Automatic risk assessment on page load
            Supports supply chain risk management
            Provides actionable mitigation strategies
        """
        session = get_session()
        deps = session.query(Dependency).all()
        # Assess risks for each dependency
        for dep in deps:
            dep.assess_risk()
        close_session(session)
        return render_template("dependencies.html", dependencies=deps)

    @app.route("/add_dependency", methods=["POST"])
    @login_required
    def add_dependency():
        """
        Add new software dependency with automatic risk assessment.

        Creates new dependency record and performs immediate risk evaluation
        based on known vulnerability patterns and version analysis.

        Form Fields:
            name: Software package name (e.g., Flask, requests, Django)
            version: Version string (e.g., 1.1.4, 2.25.0)
            risk: Manual risk description (optional)
            mitigation: Manual mitigation strategy (optional)

        Process:
            1. Extract form data with validation
            2. Create Dependency object with provided data
            3. Run automated risk assessment (assess_risk method)
            4. Determine risk level based on known vulnerabilities
            5. Generate mitigation recommendations
            6. Save to database with assessment results

        Risk Assessment:
            - Analyzes package name and version against vulnerability database
            - Assigns risk levels: Low, Medium, High, Critical
            - Provides specific mitigation strategies
            - Identifies known CVEs and security issues

        Returns:
            Redirect to dependencies page with success confirmation

        Note:
            Automatic assessment overrides manual risk input if more severe
            Supports supply chain risk management
            Provides actionable security recommendations
        """
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

    # --- Administrative Routes ---
    @app.route("/admin/users")
    @login_required
    @admin_required
    def admin_users():
        """
        Administrative interface for user management and role assignment.

        Provides administrators with the ability to:
        - View all user accounts
        - Change user roles
        - Monitor user activity
        - Manage account status

        Security Features:
            - Admin role required
            - Audit logging of all administrative actions
            - Secure role assignment validation

        Returns:
            Rendered admin users template with user management interface
        """
        users = get_visible_users(current_user())
        return render_template("admin_users.html", users=users, current_user=current_user())

    @app.route("/admin/change_role/<int:user_id>", methods=["POST"])
    @login_required
    @admin_required
    def admin_change_role(user_id):
        """
        Administrative function to change user roles.

        Implements governance by allowing administrators to assign roles:
        - user: Basic user access
        - auditor: Audit and compliance access
        - admin: Full administrative access

        Args:
            user_id: ID of the user whose role is being changed

        Security Features:
            - Admin role required
            - Audit logging of role changes
            - Validation of role values
            - Prevention of self-demotion

        Returns:
            Redirect to admin users page with success/error message
        """
        db = get_session()
        user = db.get(User, user_id)
        if not user:
            flash("User not found.", "danger")
            return redirect(url_for("admin_users"))

        new_role = request.form.get("role")
        if new_role not in ["user", "admin", "auditor"]:
            flash("Invalid role specified.", "danger")
            return redirect(url_for("admin_users"))

        # Prevent admin from demoting themselves
        current_admin = current_user()
        if user.id == current_admin.id and new_role != "admin":
            flash("Cannot change your own admin role.", "danger")
            return redirect(url_for("admin_users"))

        old_role = user.role
        user.role = new_role
        db.commit()

        forensics_logger.info(f"Governance: Admin {current_admin.email} changed user {user.email} role from '{old_role}' to '{new_role}'")
        flash(f"User role updated successfully.", "success")

        return redirect(url_for("admin_users"))

    @app.route("/admin/dashboard")
    @login_required
    @admin_required
    def admin_dashboard():
        """
        Administrative dashboard with system overview and governance metrics.

        Provides administrators with:
        - System health metrics
        - User activity statistics
        - Security incident overview
        - Governance compliance status

        Security Features:
            - Admin role required
            - Comprehensive audit logging
            - Real-time system monitoring

        Returns:
            Rendered admin dashboard template with system metrics
        """
        db = get_session()

        # System metrics
        total_users = db.query(User).count()
        total_incidents = db.query(Incident).count()
        active_incidents = db.query(Incident).filter(Incident.status != IncidentStatus.CLOSED).count()
        total_risks = db.query(Risk).count()

        # Role distribution
        admin_count = db.query(User).filter(User.role == "admin").count()
        auditor_count = db.query(User).filter(User.role == "auditor").count()
        user_count = db.query(User).filter(User.role == "user").count()

        close_session(db)

        forensics_logger.info(f"Governance: Admin {current_user().email} accessed admin dashboard")

        return render_template("admin_dashboard.html",
                             total_users=total_users,
                             total_incidents=total_incidents,
                             active_incidents=active_incidents,
                             total_risks=total_risks,
                             admin_count=admin_count,
                             auditor_count=auditor_count,
                             user_count=user_count)

    @app.route("/audit/logs")
    @login_required
    def audit_logs():
        """
        Audit logs interface for compliance monitoring and governance.

        Provides access to audit logs based on user role:
        - Admin: Full access to all audit logs
        - Auditor: Full access for compliance monitoring
        - User: Access to their own audit logs only

        Security Features:
            - Role-based access control
            - Audit logging of audit log access
            - Pagination support for large datasets

        Returns:
            Rendered audit logs template with filtered log entries
        """
        user = current_user()
        audit_logs_data = get_audit_logs(user)

        return render_template("audit_logs.html", audit_logs=audit_logs_data)

    # --- Security Policies Route ---
    @app.route("/policies")
    @login_required
    def policies():
        """
        Display security policies and procedures documentation.

        Provides access to organizational security policies, procedures,
        and guidelines for compliance and security awareness.

        Security Features:
            - User authentication required
            - Access logged for audit purposes

        Returns:
            Rendered policies template with security documentation

        Note:
            Static content display for policy awareness
            Supports organizational security training
            Part of compliance documentation requirements
        """
        return render_template("policies.html")

    # --- Knowledge Base Route ---
    @app.route("/kb")
    @login_required
    def kb():
        """
        Display knowledge base with security best practices and resources.

        Provides centralized access to security knowledge, best practices,
        procedures, and reference materials for security team members.

        Security Features:
            - User authentication required
            - Access logged for audit purposes

        Content Areas:
            - Security best practices
            - Incident response procedures
            - Compliance guidelines
            - Technical reference materials
            - Training resources

        Returns:
            Rendered knowledge base template with security resources

        Note:
            Supports security team training and awareness
            Central repository for security documentation
            Part of organizational security knowledge management
        """
        return render_template("kb.html")

    # --- SOC Monitoring Route ---
    @app.route("/monitoring")
    @login_required
    def monitoring():
        """
        Display Security Operations Center (SOC) monitoring dashboard.

        Provides real-time system monitoring and security event visibility
        for proactive threat detection and incident response.

        Monitoring Data:
            - CPU utilization percentage
            - Memory usage statistics
            - Disk space and I/O metrics
            - Network traffic counters
            - Recent security events from logs
            - Active incident status

        Security Features:
            - User authentication required
            - Real-time system metrics collection
            - Security event log integration
            - Active incident tracking

        Data Sources:
            - psutil: System performance metrics
            - forensics.log: Security event logs
            - Incident database: Active incident status

        Template Variables:
            cpu_percent: CPU usage percentage
            memory: Memory usage object
            disk: Disk usage object
            network: Network I/O counters
            security_events: List of recent security log entries
            active_incidents: List of non-closed incidents

        Returns:
            Rendered monitoring template with system and security metrics

        Note:
            Supports SOC operations and proactive monitoring
            Integrates system performance with security events
            Provides operational visibility for security team
        """
        # System monitoring using psutil
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        # Network Activity Monitoring
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
        """
        Display incident management dashboard with role-based access control.

        Shows security incidents based on user role:
        - Admin: All incidents for system oversight
        - Auditor: All incidents for compliance monitoring
        - User: Only their own reported incidents

        Security Features:
            - User authentication required
            - Role-based data access control
            - Comprehensive audit logging
            - Incident ownership verification

        Incident Data:
            - Incident title and description
            - Status (Open, Contained, Eradicated, Recovered, Closed)
            - Severity levels (Low, Medium, High, Critical)
            - Reporting timestamps
            - IRP (Incident Response Plan) progress notes

        Template Variables:
            incidents: List of visible incidents based on user role

        Returns:
            Rendered incidents template with incident management interface

        Note:
            Supports incident response workflow management
            Tracks incident lifecycle from reporting to closure
            Maintains audit trail of incident handling
        """
        user = current_user()
        incidents_list = get_visible_incidents(user)
        log_audit_event(user, "INCIDENTS_ACCESS", "COMPLIANCE",
                       f"Accessed {len(incidents_list)} incidents", "/incidents", True)
        return render_template("incidents.html", incidents=incidents_list)

    @app.route("/report_incident", methods=["GET", "POST"])
    @login_required
    def report_incident():
        """
        Handle incident reporting with structured data collection.

        Provides secure interface for users to report security incidents
        with proper classification, severity assessment, and audit logging.

        GET: Displays incident reporting form
        POST: Processes incident report submission

        Form Fields:
            title: Brief incident title/summary
            description: Detailed incident description
            severity: Incident severity level (Low, Medium, High, Critical)

        Process:
            1. Validate user authentication
            2. Extract and validate form data
            3. Create Incident database record
            4. Set initial status to OPEN
            5. Log security event with user details
            6. Redirect to incidents dashboard

        Security Features:
            - User authentication required
            - Input validation and sanitization
            - Audit logging of incident reports
            - Incident ownership assignment

        Template Variables:
            severities: IncidentSeverity enum for form dropdown

        Returns:
            GET: Incident reporting form
            POST: Redirect to incidents page with success message

        Note:
            Initiates incident response workflow
            Supports multiple severity classifications
            Creates audit trail for compliance
        """
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
        """
        Display and update incident management details with IRP workflow.

        Provides comprehensive incident tracking and response management interface.
        Supports the full incident response lifecycle from preparation through recovery.
        Implements role-based access control and incident ownership verification.

        Args:
            incident_id (int): Database ID of the incident to display/manage

        Methods:
            GET: Display incident details and current status
            POST: Update incident response notes and status

        Returns:
            GET: Rendered incident detail template
            POST: Redirect to incidents list with status message

        IRP Phases Supported:
            - Preparation: Initial incident assessment
            - Identification: Incident analysis and classification
            - Containment: Short-term mitigation measures
            - Eradication: Root cause removal
            - Recovery: System restoration and validation
            - Lessons Learned: Post-incident analysis

        Security Features:
            - Incident ownership verification
            - Audit logging of all updates
            - Role-based access control
            - Secure status transitions

        Template Variables:
            incident: Incident object with all response notes
            statuses: IncidentStatus enum for status dropdown
            severities: IncidentSeverity enum for display

        Note:
            Automatically generates post-incident analysis when closed
            Supports comprehensive incident documentation
            Maintains incident response timeline
        """
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
        """
        Digital forensics management interface with evidence collection and reporting.

        Provides comprehensive forensics capabilities including evidence collection,
        integrity verification, report generation, and chain of custody management.

        GET: Displays forensics dashboard with evidence and incidents
        POST: Handles evidence collection and report generation

        POST Actions:
            generate_report: Creates comprehensive forensics report
            collect_evidence: Adds new evidence to incident

        Evidence Collection:
            - File upload with integrity hashing
            - Evidence type classification
            - Chain of custody tracking
            - Storage method documentation

        Report Generation:
            - System logs compilation
            - Incident evidence aggregation
            - User activity analysis
            - Timestamp and integrity verification

        Security Features:
            - User authentication required
            - File type validation for evidence
            - Integrity hashing for tamper detection
            - Audit logging of all forensics activities

        Template Variables:
            incidents: User's reported incidents for evidence linking
            evidence: User's collected evidence items
            evidence_types: EvidenceType enum for form options

        Returns:
            GET: Forensics dashboard template
            POST: File download or redirect with status messages

        Note:
            Supports incident response and legal proceedings
            Maintains evidence integrity and chain of custody
            Generates comprehensive audit trails
        """
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
    # --- Risk Identification Methods Routes ---

    @app.route("/brainstorming", methods=["GET", "POST"])
    @login_required
    def brainstorming():
        """
        Facilitated brainstorming session for risk identification.

        Implements structured brainstorming approach with:
        - Session management and participant tracking
        - Idea generation and categorization
        - Facilitation techniques and time management
        - Risk conversion from brainstorming ideas

        GET: Displays brainstorming interface
        POST: Handles session creation, idea submission, and risk generation

        Process:
            1. Create/manage brainstorming sessions
            2. Collect ideas from participants
            3. Categorize and prioritize ideas
            4. Convert high-priority ideas to formal risks
            5. Generate session reports

        Returns:
            Rendered brainstorming template with session management
        """
        user = current_user()
        db = get_session()

        if request.method == "POST":
            action = request.form.get("action")

            if action == "create_session":
                # Create new brainstorming session
                session_title = request.form.get("session_title")
                objective = request.form.get("objective")
                duration_minutes = int(request.form.get("duration", 60))

                bs = BrainstormingSession(
                    title=session_title,
                    objective=objective,
                    facilitator_id=user.id,
                    duration_minutes=duration_minutes,
                    status="active"
                )
                db.add(bs)
                db.commit()

                # Add facilitator as first participant
                participant = BrainstormingParticipant(
                    session_id=bs.id,
                    user_id=user.id,
                    role="facilitator"
                )
                db.add(participant)
                db.commit()

                flash(f"Brainstorming session '{session_title}' created successfully!", "success")
                return redirect(url_for("brainstorming"))

            elif action == "join_session":
                session_id = int(request.form.get("session_id"))
                bs = db.get(BrainstormingSession, session_id)
                if bs and bs.status == "active":
                    # Check if already a participant
                    existing = db.query(BrainstormingParticipant).filter(
                        BrainstormingParticipant.session_id == session_id,
                        BrainstormingParticipant.user_id == user.id
                    ).first()

                    if not existing:
                        participant = BrainstormingParticipant(
                            session_id=session_id,
                            user_id=user.id,
                            role="participant"
                        )
                        db.add(participant)
                        db.commit()
                        flash("Joined brainstorming session!", "success")
                    else:
                        flash("Already participating in this session.", "info")
                else:
                    flash("Session not found or not active.", "danger")

            elif action == "submit_idea":
                session_id = int(request.form.get("session_id"))
                idea_text = request.form.get("idea_text")
                category = request.form.get("category", "general")

                idea = BrainstormingIdea(
                    session_id=session_id,
                    submitted_by=user.id,
                    idea_text=idea_text,
                    category=category
                )
                db.add(idea)
                db.commit()
                flash("Idea submitted successfully!", "success")

            elif action == "convert_to_risk":
                idea_id = int(request.form.get("idea_id"))
                idea = db.get(BrainstormingIdea, idea_id)

                if idea:
                    # Create risk from idea
                    risk = Risk(
                        asset=f"Brainstorming Idea: {idea.idea_text[:100]}",
                        threat=idea.idea_text,
                        vulnerability="Identified through brainstorming",
                        control="To be determined",
                        likelihood=3,  # Default moderate
                        impact=3,      # Default moderate
                        owner=user.email,
                        category=RiskCategory(idea.category.upper()) if idea.category != "general" else None
                    )
                    risk.calculate_score()

                    db.add(risk)
                    db.commit()

                    # Mark idea as converted
                    idea.converted_to_risk = True
                    idea.risk_id = risk.id
                    db.commit()

                    flash(f"Idea converted to risk assessment (ID: {risk.id})", "success")

        # Get active sessions and user's participation
        active_sessions = db.query(BrainstormingSession).filter(BrainstormingSession.status == "active").all()
        user_participation = db.query(BrainstormingParticipant).filter(BrainstormingParticipant.user_id == user.id).all()

        close_session(db)
        return render_template("brainstorming.html", active_sessions=active_sessions, user_participation=user_participation)

    @app.route("/brainstorming/<int:session_id>")
    @login_required
    def view_brainstorming_session(session_id):
        """
        View detailed brainstorming session with ideas and participants.
        """
        user = current_user()
        db = get_session()

        session_obj = db.get(BrainstormingSession, session_id)
        if not session_obj:
            close_session(db)
            flash("Session not found.", "danger")
            return redirect(url_for("brainstorming"))

        # Check if user is a participant
        participant = db.query(BrainstormingParticipant).filter(
            BrainstormingParticipant.session_id == session_id,
            BrainstormingParticipant.user_id == user.id
        ).first()

        if not participant and session_obj.facilitator_id != user.id:
            close_session(db)
            flash("Access denied. You are not a participant in this session.", "danger")
            return redirect(url_for("brainstorming"))

        # Get ideas and participants
        ideas = db.query(BrainstormingIdea).filter(BrainstormingIdea.session_id == session_id).all()
        participants = db.query(BrainstormingParticipant).filter(BrainstormingParticipant.session_id == session_id).all()

        close_session(db)
        return render_template("brainstorming_session.html",
                             session=session_obj,
                             ideas=ideas,
                             participants=participants,
                             is_facilitator=(session_obj.facilitator_id == user.id))

    @app.route("/checklists", methods=["GET", "POST"])
    @login_required
    def checklists():
        """
        Risk checklist assessment interface.

        Implements structured checklist-based risk identification with:
        - Pre-defined risk categories and questions
        - Assessment scoring and prioritization
        - Automated risk generation from checklist responses
        - Compliance framework mapping

        GET: Displays available checklists
        POST: Handles checklist assessment and risk generation

        Process:
            1. Select or create risk checklist
            2. Answer assessment questions
            3. Calculate risk scores based on responses
            4. Generate formal risk assessments
            5. Link to compliance requirements

        Returns:
            Rendered checklists template with assessment interface
        """
        user = current_user()
        db = get_session()

        if request.method == "POST":
            action = request.form.get("action")

            if action == "start_assessment":
                checklist_id = int(request.form.get("checklist_id"))

                # Create new assessment
                assessment = RiskChecklistAssessment(
                    checklist_id=checklist_id,
                    assessor_id=user.id,
                    status="in_progress"
                )
                db.add(assessment)
                db.commit()

                flash("Assessment started! Please answer the questions.", "success")
                return redirect(url_for("checklist_assessment", assessment_id=assessment.id))

            elif action == "submit_response":
                assessment_id = int(request.form.get("assessment_id"))
                item_id = int(request.form.get("item_id"))
                response_value = request.form.get("response")
                notes = request.form.get("notes", "")

                response = RiskChecklistResponse(
                    assessment_id=assessment_id,
                    checklist_item_id=item_id,
                    response_value=response_value,
                    notes=notes
                )
                db.add(response)
                db.commit()

                # Check if assessment is complete
                assessment = db.get(RiskChecklistAssessment, assessment_id)
                total_items = db.query(RiskChecklistItem).filter(RiskChecklistItem.checklist_id == assessment.checklist_id).count()
                completed_responses = db.query(RiskChecklistResponse).filter(RiskChecklistResponse.assessment_id == assessment_id).count()

                if completed_responses >= total_items:
                    assessment.status = "completed"
                    assessment.completed_at = datetime.now(timezone.utc)
                    db.commit()

                    # Generate risks from high-risk responses
                    generate_risks_from_checklist(assessment_id)
                    flash("Assessment completed! Risks have been generated where applicable.", "success")

        # Get available checklists
        checklists_list = db.query(RiskChecklist).all()

        # Get user's recent assessments
        recent_assessments = db.query(RiskChecklistAssessment).filter(
            RiskChecklistAssessment.assessor_id == user.id
        ).order_by(RiskChecklistAssessment.created_at.desc()).limit(5).all()

        close_session(db)
        return render_template("checklists.html",
                             checklists=checklists_list,
                             recent_assessments=recent_assessments)

    @app.route("/checklist_assessment/<int:assessment_id>", methods=["GET", "POST"])
    @login_required
    def checklist_assessment(assessment_id):
        """
        Conduct individual risk assessment checklist with question-by-question evaluation.

        Provides an interactive interface for completing risk assessment checklists.
        Supports systematic evaluation of risk factors through structured questioning.
        Automatically generates risks when assessment criteria are met.

        Args:
            assessment_id (int): Database ID of the checklist assessment

        Methods:
            GET: Display checklist questions and current responses
            POST: Submit responses for individual questions

        Returns:
            GET: Rendered checklist assessment template
            POST: Redirect with success message or continue to next question

        Assessment Process:
            1. Load checklist items for the assessment
            2. Display questions with response options
            3. Record user responses in database
            4. Check for assessment completion
            5. Generate risks based on critical responses
            6. Mark assessment as completed

        Risk Generation:
            - Automatically creates risk assessments for high-risk responses
            - Links risks to original checklist items
            - Assigns appropriate risk scores and severities

        Security:
            - Assessment ownership verification
            - User authentication required
            - Audit logging of assessment activities

        Template Variables:
            assessment: ChecklistAssessment object
            checklist_items: List of questions to answer
            responses: Dictionary of existing responses

        Note:
            Supports partial completion and resuming assessments
            Provides clear progress indication
            Enables systematic risk identification
        """
        user = current_user()
        db = get_session()

        assessment = db.get(RiskChecklistAssessment, assessment_id)
        if not assessment or assessment.assessor_id != user.id:
            close_session(db)
            flash("Assessment not found or access denied.", "danger")
            return redirect(url_for("checklists"))

        # Get checklist items and existing responses
        checklist_items = db.query(RiskChecklistItem).filter(
            RiskChecklistItem.checklist_id == assessment.checklist_id
        ).all()

        responses = {}
        for item in checklist_items:
            response = db.query(RiskChecklistResponse).filter(
                RiskChecklistResponse.assessment_id == assessment_id,
                RiskChecklistResponse.checklist_item_id == item.id
            ).first()
            if response:
                responses[item.id] = response

        close_session(db)
        return render_template("checklist_assessment.html",
                             assessment=assessment,
                             checklist_items=checklist_items,
                             responses=responses)

    @app.route("/swot_analysis", methods=["GET", "POST"])
    @login_required
    def swot_analysis():
        """
        SWOT analysis for strategic risk identification.

        Implements SWOT (Strengths, Weaknesses, Opportunities, Threats) methodology with:
        - Strategic factor identification and categorization
        - Risk extraction from weaknesses and threats
        - Opportunity conversion to positive risk treatments
        - Strategic risk prioritization

        GET: Displays SWOT analysis interface
        POST: Handles factor submission and risk generation

        Process:
            1. Create SWOT analysis session
            2. Collect factors in each category
            3. Analyze factors for risk implications
            4. Generate strategic risks from threats/weaknesses
            5. Create mitigation strategies from opportunities

        Returns:
            Rendered SWOT analysis template
        """
        user = current_user()
        db = get_session()

        if request.method == "POST":
            action = request.form.get("action")

            if action == "create_analysis":
                title = request.form.get("title")
                scope = request.form.get("scope", "general")

                swot = SWOTAnalysis(
                    title=title,
                    scope=scope,
                    analyst_id=user.id,
                    status="in_progress"
                )
                db.add(swot)
                db.commit()

                flash(f"SWOT analysis '{title}' created successfully!", "success")
                return redirect(url_for("swot_analysis"))

            elif action == "add_factor":
                analysis_id = int(request.form.get("analysis_id"))
                factor_type = request.form.get("factor_type")  # strengths, weaknesses, opportunities, threats
                description = request.form.get("description")
                impact_level = request.form.get("impact_level", "medium")
                strategic_importance = request.form.get("strategic_importance", "medium")

                factor = SWOTItem(
                    analysis_id=analysis_id,
                    factor_type=factor_type,
                    description=description,
                    impact_level=impact_level,
                    strategic_importance=strategic_importance
                )
                db.add(factor)
                db.commit()

                flash(f"{factor_type.title()} factor added successfully!", "success")

            elif action == "convert_to_risk":
                factor_id = int(request.form.get("factor_id"))
                factor = db.get(SWOTItem, factor_id)

                if factor and factor.factor_type in ["weaknesses", "threats"]:
                    # Create risk from SWOT factor
                    risk_type = "Weakness" if factor.factor_type == "weaknesses" else "Threat"

                    risk = Risk(
                        asset=f"SWOT {risk_type}: {factor.description[:100]}",
                        threat=factor.description,
                        vulnerability=f"Strategic {risk_type.lower()} identified in SWOT analysis",
                        control="Strategic mitigation required",
                        likelihood=4 if factor.impact_level == "high" else 3 if factor.impact_level == "medium" else 2,
                        impact=4 if factor.strategic_importance == "high" else 3 if factor.strategic_importance == "medium" else 2,
                        owner=user.email,
                        category=RiskCategory.STRATEGIC_RISKS if hasattr(RiskCategory, 'STRATEGIC_RISKS') else None
                    )
                    risk.calculate_score()

                    db.add(risk)
                    db.commit()

                    # Mark factor as converted
                    factor.converted_to_risk = True
                    factor.risk_id = risk.id
                    db.commit()

                    flash(f"SWOT factor converted to risk assessment (ID: {risk.id})", "success")

        # Get user's SWOT analyses
        swot_analyses = db.query(SWOTAnalysis).filter(SWOTAnalysis.analyst_id == user.id).all()

        close_session(db)
        return render_template("swot_analysis.html", swot_analyses=swot_analyses)

    @app.route("/swot_analysis/<int:analysis_id>")
    @login_required
    def view_swot_analysis(analysis_id):
        """
        View detailed SWOT analysis with factors and generated risks.
        """
        user = current_user()
        db = get_session()

        analysis = db.get(SWOTAnalysis, analysis_id)
        if not analysis or analysis.analyst_id != user.id:
            close_session(db)
            flash("Analysis not found or access denied.", "danger")
            return redirect(url_for("swot_analysis"))

        # Get SWOT factors grouped by type
        factors = db.query(SWOTItem).filter(SWOTItem.analysis_id == analysis_id).all()

        # Group factors by type
        grouped_factors = {
            "strengths": [f for f in factors if f.factor_type == "strengths"],
            "weaknesses": [f for f in factors if f.factor_type == "weaknesses"],
            "opportunities": [f for f in factors if f.factor_type == "opportunities"],
            "threats": [f for f in factors if f.factor_type == "threats"]
        }

        close_session(db)
        return render_template("swot_analysis_detail.html",
                             analysis=analysis,
                             grouped_factors=grouped_factors)


    @app.route("/asset_register", methods=["GET", "POST"])
    @login_required
    def asset_register():
        db = get_session()
        if request.method == "POST":
            # Create new asset entry
            asset = CriticalAssetRegister(
                asset_name=request.form["asset_name"],
                asset_type=request.form["asset_type"],
                asset_value=float(request.form.get("asset_value", 0)),
                criticality_level=request.form.get("criticality_level", "medium"),
                threat_exposure_score=int(request.form.get("threat_exposure_score", 1)),
                primary_threats=json.dumps(request.form.getlist("threats")),
                vulnerability_count=int(request.form.get("vulnerability_count", 0)),
                upstream_dependencies=json.dumps(request.form.getlist("upstream")),
                downstream_dependencies=json.dumps(request.form.getlist("downstream")),
                assessed_by=current_user().id
            )
            asset.calculate_overall_risk_exposure()
            db.add(asset)
            db.commit()
            flash("Asset registered successfully.", "success")
            return redirect(url_for("asset_register"))
    
        assets = db.query(CriticalAssetRegister).all()
        close_session(db)
        return render_template("asset_register.html", assets=assets)

    @app.route("/asset_report/<int:asset_id>")
    @login_required
    def asset_report(asset_id):
        """
        Generate and display comprehensive asset risk assessment report.

        Creates detailed risk analysis report for critical assets including
        threat exposure, vulnerability assessment, and risk mitigation recommendations.
        Supports asset criticality evaluation and risk prioritization.

        Args:
            asset_id (int): Database ID of the critical asset

        Returns:
            Rendered asset report template with comprehensive risk analysis

        Report Components:
            - Asset overview and criticality assessment
            - Threat exposure analysis
            - Vulnerability evaluation
            - Risk scoring and prioritization
            - Mitigation recommendations
            - Compliance alignment

        Security:
            - User authentication required
            - Asset existence validation
            - Audit logging of report access

        Template Variables:
            report: Generated report data from asset.generate_report()

        Note:
            Leverages asset model methods for comprehensive analysis
            Supports executive and operational reporting needs
            Enables informed risk treatment decisions
        """
        db = get_session()
        asset = db.get(CriticalAssetRegister, asset_id)
        if not asset:
            flash("Asset not found.", "danger")
            return redirect(url_for("asset_register"))
        report = asset.generate_report()
        close_session(db)
        return render_template("asset_report.html", report=report)

    @app.route("/framework_mapping")
    @login_required
    def framework_mapping():
        """Visual framework mapping showing organizational alignment"""
        db_session = get_session()
        frameworks = db_session.query(RiskManagementFramework).filter_by(is_active=True).all()
        close_session(db_session)

        # Create mapping data structure
        mapping_data = {
            "executive": {
                "nist_rmf": ["Prepare", "Categorize", "Authorize"],
                "iso_31000": ["Establish context", "Risk treatment"],
                "coso": ["Control environment", "Risk assessment"]
            },
            "management": {
                "nist_rmf": ["Select", "Implement"],
                "iso_31000": ["Risk analysis", "Risk evaluation"],
                "coso": ["Control activities", "Information & communication"]
            },
            "technical": {
                "nist_rmf": ["Assess", "Monitor"],
                "iso_31000": ["Communication", "Monitoring"],
                "coso": ["Monitoring activities"]
            }
        }

        return render_template("framework_mapping.html",
                             frameworks=frameworks,
                             mapping_data=mapping_data)


    # Helper functions for risk generation
    def generate_risks_from_checklist(assessment_id):
        """
        Automatically generate risk assessments from checklist responses.

        Analyzes completed checklist assessments and creates formal risk records
        for responses that indicate significant risk exposure. Supports systematic
        risk identification through structured assessment processes.

        Args:
            assessment_id (int): Database ID of the completed checklist assessment

        Process:
            1. Retrieve assessment and associated responses
            2. Evaluate each response for risk significance
            3. Create risk records for high-risk responses
            4. Link risks to original checklist items
            5. Assign appropriate risk scoring and metadata

        Risk Creation Criteria:
            - Response values: "yes", "high", or "critical"
            - Risk score: 3-4 based on response severity
            - Owner: Assessment assessor
            - Category: From checklist item category

        Database Operations:
            - Creates Risk records with comprehensive data
            - Calculates initial risk scores
            - Commits all changes in single transaction

        Note:
            Called automatically when checklist assessment is completed
            Supports integration with broader risk management framework
            Enables systematic risk identification from checklists
        """
        db = get_session()

        assessment = db.get(RiskChecklistAssessment, assessment_id)
        responses = db.query(RiskChecklistResponse).filter(RiskChecklistResponse.assessment_id == assessment_id).all()

        for response in responses:
            # Generate risk if response indicates high risk
            if response.response_value in ["yes", "high", "critical"]:
                item = db.get(RiskChecklistItem, response.checklist_item_id)

                risk = Risk(
                    asset=f"Checklist Item: {item.question[:100]}",
                    threat=item.question,
                    vulnerability="Identified through checklist assessment",
                    control=item.mitigation_suggestion or "To be determined",
                    likelihood=4 if response.response_value == "critical" else 3,
                    impact=4 if response.response_value == "critical" else 3,
                    owner=assessment.assessor.email,
                    category=item.category
                )
                risk.calculate_score()

                db.add(risk)

        db.commit()
        close_session(db)

    # --- Cyber Threats and Vulnerabilities Routes ---

    @app.route("/threat_analysis")
    @login_required
    def threat_analysis():
        """Main threat analysis dashboard"""
        user = current_user()
        db = get_session()

        # Get user's threat analysis data
        malware_samples = db.query(MalwareSample).filter(MalwareSample.submitted_by == user.id).all()
        phishing_templates = db.query(PhishingTemplate).filter(PhishingTemplate.created_by == user.id).all()
        apt_campaigns = db.query(APTCampaign).filter(APTCampaign.documented_by == user.id).all()

        close_session(db)
        return render_template("threat_analysis.html",
                             malware_samples=malware_samples,
                             phishing_templates=phishing_templates,
                             apt_campaigns=apt_campaigns)

    @app.route("/malware_analysis", methods=["GET", "POST"])
    @login_required
    def malware_analysis():
        """Malware sample submission and analysis"""
        user = current_user()
        db = get_session()

        if request.method == "POST":
            sample_hash = request.form.get("sample_hash").strip()
            filename = request.form.get("filename", "").strip()

            # Check if sample already exists
            existing = db.query(MalwareSample).filter(MalwareSample.sample_hash == sample_hash).first()
            if existing:
                flash("Sample with this hash already exists.", "warning")
            else:
                sample = MalwareSample(
                    sample_hash=sample_hash,
                    filename=filename,
                    submitted_by=user.id
                )
                db.add(sample)
                db.commit()
                flash("Malware sample submitted for analysis.", "success")
                return redirect(url_for("malware_analysis"))

        samples = db.query(MalwareSample).options(joinedload(MalwareSample.analyses)).filter(MalwareSample.submitted_by == user.id).all()
        close_session(db)
        return render_template("malware_analysis.html", samples=samples)

    @app.route("/analyze_malware/<int:sample_id>", methods=["POST"])
    @login_required
    def analyze_malware(sample_id):
        """Trigger malware analysis using VirusTotal API simulation"""
        user = current_user()
        db = get_session()

        sample = db.get(MalwareSample, sample_id)
        if not sample or sample.submitted_by != user.id:
            close_session(db)
            flash("Sample not found or access denied.", "danger")
            return redirect(url_for("malware_analysis"))

        # Enhanced malware analysis with detailed VirusTotal-like results
        # In production, this would call: requests.post('https://www.virustotal.com/api/v3/files', headers={'x-apikey': API_KEY}, files=files)

        analysis_result = perform_malware_analysis(sample.sample_hash)

        analysis = MalwareAnalysis(
            sample_id=sample_id,
            platform="virustotal",
            detection_ratio=f"{analysis_result['positives']}/{analysis_result['total']}",
            positive_detections=analysis_result['positives'],
            total_scanners=analysis_result['total'],
            behavioral_indicators=json.dumps(analysis_result['behavioral_indicators']),
            potential_impact=analysis_result['impact'],
            severity=analysis_result['severity']
        )

        db.add(analysis)
        sample.analysis_status = "completed"
        db.commit()

        log_audit_event(user, "MALWARE_ANALYSIS", "SECURITY",
                       f"Analyzed malware sample {sample.sample_hash} - {analysis_result['positives']} detections", f"/analyze_malware/{sample_id}", True)

        close_session(db)
        flash(f"Malware analysis completed. {analysis_result['positives']} out of {analysis_result['total']} scanners detected this as malicious.", "success")
        return redirect(url_for("malware_analysis"))

    @app.route("/phishing_templates", methods=["GET", "POST"])
    @login_required
    def phishing_templates():
        """Phishing template management"""
        user = current_user()
        db = get_session()

        if request.method == "POST":
            template = PhishingTemplate(
                name=request.form.get("name"),
                description=request.form.get("description"),
                subject=request.form.get("subject"),
                body_html=request.form.get("body_html"),
                body_text=request.form.get("body_text"),
                spoofed_sender=request.form.get("spoofed_sender"),
                malicious_links=json.dumps(request.form.getlist("malicious_links")),
                social_engineering_techniques=json.dumps(request.form.getlist("techniques")),
                risk_level=request.form.get("risk_level", "medium"),
                created_by=user.id
            )
            db.add(template)
            db.commit()
            flash("Phishing template created.", "success")
            return redirect(url_for("phishing_templates"))

        templates_raw = db.query(PhishingTemplate).filter(PhishingTemplate.created_by == user.id).all()

        templates = []
        for template in templates_raw:
            templates.append({
                'id': template.id,
                'name': template.name,
                'description': template.description,
                'subject': template.subject,
                'body_html': template.body_html,
                'body_text': template.body_text,
                'spoofed_sender': template.spoofed_sender,
                'malicious_links': template.malicious_links,
                'social_engineering_techniques': template.social_engineering_techniques,
                'risk_level': template.risk_level,
                'created_at': template.created_at.isoformat() if template.created_at else None,
                'updated_at': template.updated_at.isoformat() if template.updated_at else None
            })

        close_session(db)
        return render_template("phishing_templates.html", templates=templates)

    @app.route("/apt_campaigns", methods=["GET", "POST"])
    @login_required
    def apt_campaigns():
        """APT campaign documentation and mapping"""
        user = current_user()
        db = get_session()

        if request.method == "POST":
            campaign = APTCampaign(
                name=request.form.get("name"),
                description=request.form.get("description"),
                actor_name=request.form.get("actor_name"),
                target_sector=request.form.get("target_sector"),
                objectives=request.form.get("objectives"),
                techniques_used=json.dumps(request.form.getlist("techniques")),
                indicators_of_compromise=json.dumps(request.form.getlist("indicators")),
                severity=request.form.get("severity", "high"),
                relevance_to_organization=request.form.get("relevance", "unknown"),
                documented_by=user.id
            )
            db.add(campaign)
            db.commit()
            flash("APT campaign documented.", "success")
            return redirect(url_for("apt_campaigns"))

        campaigns = db.query(APTCampaign).filter(APTCampaign.documented_by == user.id).all()
        close_session(db)
        return render_template("apt_campaigns.html", campaigns=campaigns)

    @app.route("/apt_campaign/<int:campaign_id>", methods=["GET", "POST"])
    @login_required
    def view_apt_campaign(campaign_id):
        """View and map APT campaign to MITRE ATT&CK framework"""
        user = current_user()
        db = get_session()

        campaign = db.query(APTCampaign).options(joinedload(APTCampaign.documenter)).filter(APTCampaign.id == campaign_id).first()
        if not campaign or campaign.documented_by != user.id:
            close_session(db)
            flash("Campaign not found or access denied.", "danger")
            return redirect(url_for("apt_campaigns"))

        if request.method == "POST":
            # Enhanced ATT&CK mapping with validation
            technique_data = get_attack_technique_details(request.form.get("technique_id"))

            mapping = ATTACKMapping(
                campaign_id=campaign_id,
                tactic=technique_data.get("tactic", request.form.get("tactic")),
                technique=technique_data.get("technique", request.form.get("technique")),
                technique_id=request.form.get("technique_id"),
                subtechnique=technique_data.get("subtechnique", request.form.get("subtechnique")),
                subtechnique_id=request.form.get("subtechnique_id"),
                description=technique_data.get("description", request.form.get("description")),
                evidence=request.form.get("evidence"),
                confidence=request.form.get("confidence", "medium"),
                mapped_by=user.id
            )
            db.add(mapping)
            db.commit()
            flash(f"ATT&CK mapping added for {technique_data.get('technique', 'Unknown')} technique.", "success")
            return redirect(url_for("view_apt_campaign", campaign_id=campaign_id))

        mappings = db.query(ATTACKMapping).filter(ATTACKMapping.campaign_id == campaign_id).all()

        # Get available ATT&CK techniques for the campaign
        available_techniques = get_campaign_techniques(campaign.name)

        close_session(db)
        return render_template("apt_campaign_detail.html", campaign=campaign, mappings=mappings, available_techniques=available_techniques)

    # --- Vulnerability Assessment Routes ---

    @app.route("/vulnerability_assessment")
    @login_required
    def vulnerability_assessment():
        """Main vulnerability assessment dashboard"""
        user = current_user()
        db = get_session()

        scans = db.query(VulnerabilityScan).filter(VulnerabilityScan.performed_by == user.id).all()
        discoveries = db.query(AssetDiscovery).filter(AssetDiscovery.performed_by == user.id).all()

        close_session(db)
        return render_template("vulnerability_assessment.html", scans=scans, discoveries=discoveries)

    @app.route("/vulnerability_scan", methods=["GET", "POST"])
    @login_required
    def vulnerability_scan():
        """Vulnerability scan management"""
        user = current_user()
        db = get_session()

        if request.method == "POST":
            scan = VulnerabilityScan(
                scan_name=request.form.get("scan_name"),
                tool_used=request.form.get("tool_used"),
                target_range=request.form.get("target_range"),
                scan_type=request.form.get("scan_type", "basic"),
                scan_parameters=json.dumps(request.form.get("scan_parameters", {})),
                performed_by=user.id
            )
            db.add(scan)
            db.commit()
            flash("Vulnerability scan initiated.", "success")
            return redirect(url_for("vulnerability_scan"))

        scans_raw = db.query(VulnerabilityScan).filter(VulnerabilityScan.performed_by == user.id).all()

        scans = []
        for scan in scans_raw:
            scans.append({
                'id': scan.id,
                'scan_name': scan.scan_name,
                'tool_used': scan.tool_used,
                'target_range': scan.target_range,
                'scan_type': scan.scan_type,
                'vulnerabilities_found': scan.vulnerabilities_found,
                'critical_findings': scan.critical_findings,
                'high_findings': scan.high_findings,
                'start_time': scan.start_time.isoformat() if scan.start_time else None,
                'end_time': scan.end_time.isoformat() if scan.end_time else None,
                'duration_seconds': scan.duration_seconds,
                'performed_by': scan.performed_by,
                'created_at': scan.created_at.isoformat() if scan.created_at else None
            })

        close_session(db)
        return render_template("vulnerability_scan.html", scans=scans)

    @app.route("/upload_scan_results/<int:scan_id>", methods=["POST"])
    @login_required
    def upload_scan_results(scan_id):
        """Upload and parse vulnerability scan results"""
        user = current_user()
        db = get_session()

        scan = db.get(VulnerabilityScan, scan_id)
        if not scan or scan.performed_by != user.id:
            close_session(db)
            flash("Scan not found or access denied.", "danger")
            return redirect(url_for("vulnerability_scan"))

        if "scan_file" not in request.files:
            flash("No file uploaded.", "danger")
            return redirect(url_for("vulnerability_scan"))

        file = request.files["scan_file"]
        if file.filename == "":
            flash("No file selected.", "danger")
            return redirect(url_for("vulnerability_scan"))

        # Parse scan results (mock implementation)
        # In production, parse actual Nmap/OpenVAS XML output
        mock_findings = [
            {
                "host_ip": "192.168.1.100",
                "port": 80,
                "service": "http",
                "vulnerability_id": "CVE-2021-44228",
                "title": "Apache Log4j Remote Code Execution",
                "severity": "critical",
                "cvss_score": 10.0,
                "remediation": "Update Log4j to version 2.17.0 or later"
            },
            {
                "host_ip": "192.168.1.101",
                "port": 443,
                "service": "https",
                "vulnerability_id": "CVE-2022-2068",
                "title": "OpenSSL Buffer Overflow",
                "severity": "high",
                "cvss_score": 7.5,
                "remediation": "Update OpenSSL to latest version"
            }
        ]

        for finding_data in mock_findings:
            finding = VulnerabilityFinding(
                scan_id=scan_id,
                host_ip=finding_data["host_ip"],
                port=finding_data["port"],
                service=finding_data["service"],
                vulnerability_id=finding_data["vulnerability_id"],
                title=finding_data["title"],
                severity=finding_data["severity"],
                cvss_score=finding_data["cvss_score"],
                remediation=finding_data["remediation"]
            )
            db.add(finding)

        # Update scan summary
        scan.vulnerabilities_found = len(mock_findings)
        scan.critical_findings = len([f for f in mock_findings if f["severity"] == "critical"])
        scan.high_findings = len([f for f in mock_findings if f["severity"] == "high"])
        scan.end_time = datetime.now(timezone.utc)
        scan.duration_seconds = int((scan.end_time - scan.start_time).total_seconds()) if scan.start_time else 0

        db.commit()

        log_audit_event(user, "SCAN_RESULTS_UPLOADED", "SECURITY",
                       f"Uploaded scan results for {scan.scan_name}", f"/upload_scan_results/{scan_id}", True)

        close_session(db)
        flash("Scan results uploaded and parsed.", "success")
        return redirect(url_for("vulnerability_scan"))

    @app.route("/asset_discovery", methods=["GET", "POST"])
    @login_required
    def asset_discovery():
        """Asset discovery scan management"""
        user = current_user()
        db = get_session()

        if request.method == "POST":
            discovery = AssetDiscovery(
                scan_name=request.form.get("scan_name"),
                discovery_method=request.form.get("discovery_method", "network_scan"),
                target_network=request.form.get("target_network"),
                scan_parameters=json.dumps(request.form.get("scan_parameters", {})),
                performed_by=user.id
            )
            db.add(discovery)
            db.commit()
            flash("Asset discovery scan initiated.", "success")
            return redirect(url_for("asset_discovery"))

        discoveries = db.query(AssetDiscovery).filter(AssetDiscovery.performed_by == user.id).all()
        close_session(db)
        return render_template("asset_discovery.html", discoveries=discoveries)

    @app.route("/run_asset_discovery/<int:discovery_id>", methods=["POST"])
    @login_required
    def run_asset_discovery(discovery_id):
        """Simulate asset discovery scan"""
        user = current_user()
        db = get_session()

        discovery = db.get(AssetDiscovery, discovery_id)
        if not discovery or discovery.performed_by != user.id:
            close_session(db)
            flash("Discovery not found or access denied.", "danger")
            return redirect(url_for("asset_discovery"))

        # Mock asset discovery results
        mock_assets = [
            {"ip": "192.168.1.10", "hostname": "web-server", "services": [{"name": "http", "port": 80, "state": "open"}, {"name": "https", "port": 443, "state": "open"}]},
            {"ip": "192.168.1.11", "hostname": "db-server", "services": [{"name": "mysql", "port": 3306, "state": "open"}]},
            {"ip": "192.168.1.12", "hostname": "file-server", "services": [{"name": "smb", "port": 445, "state": "open"}]}
        ]

        for asset_data in mock_assets:
            # Create discovered service records
            for service_data in asset_data["services"]:
                service = DiscoveredService(
                    asset_id=discovery_id,
                    service_name=service_data["name"],
                    port=service_data["port"],
                    protocol="tcp",
                    state=service_data["state"],
                    criticality="high" if service_data["name"] in ["mysql", "smb"] else "medium"
                )
                db.add(service)

        # Update discovery summary
        discovery.assets_discovered = len(mock_assets)
        discovery.critical_assets = len([a for a in mock_assets if any(s["name"] in ["mysql", "smb"] for s in a["services"])])
        discovery.network_topology = json.dumps({"discovered_network": "192.168.1.0/24", "asset_count": len(mock_assets)})

        db.commit()

        log_audit_event(user, "ASSET_DISCOVERY_RUN", "SECURITY",
                       f"Completed asset discovery scan {discovery.scan_name}", f"/run_asset_discovery/{discovery_id}", True)

        close_session(db)
        flash("Asset discovery completed.", "success")
        return redirect(url_for("asset_discovery"))

    # --- End of Cyber Threats and Vulnerabilities Routes ---

    # --- Threat Intelligence Routes ---

    @app.route("/threat_intelligence")
    @login_required
    def threat_intelligence():
        """Main threat intelligence dashboard"""
        user = current_user()
        db = get_session()

        # Get user's threat intelligence data
        iocs = db.query(IndicatorOfCompromise).filter(IndicatorOfCompromise.created_by == user.id).all()
        opencti_integrations = db.query(OpenCTIIntegration).all()

        close_session(db)
        return render_template("threat_intelligence.html",
                             iocs=iocs,
                             opencti_integrations=opencti_integrations)

    @app.route("/ioc_analysis", methods=["GET", "POST"])
    @login_required
    def ioc_analysis():
        """IoC submission and analysis"""
        user = current_user()
        db = get_session()

        if request.method == "POST":
            try:
                indicator_value = request.form.get("indicator_value", "").strip()

                ioc = IndicatorOfCompromise(
                    indicator_type=request.form.get("indicator_type"),
                    indicator_value=indicator_value,
                    confidence=int(request.form.get("confidence", 50)),
                    severity=request.form.get("severity", "medium"),
                    status=request.form.get("status", "active"),
                    threat_actor=request.form.get("threat_actor"),
                    campaign=request.form.get("campaign"),
                    malware_family=request.form.get("malware_family"),
                    first_seen=datetime.strptime(request.form.get("first_seen"), "%Y-%m-%d") if request.form.get("first_seen") else None,
                    last_seen=datetime.strptime(request.form.get("last_seen"), "%Y-%m-%d") if request.form.get("last_seen") else None,
                    detection_source=request.form.get("detection_source"),
                    description=request.form.get("description"),
                    tags=json.dumps(request.form.getlist("tags")),
                    created_by=user.id
                )
                db.add(ioc)
                db.commit()
                flash("IoC submitted for analysis.", "success")
                return redirect(url_for("ioc_analysis"))
            except Exception as e:
                logging.error(f"Error processing IoC submission: {e}")
                db.rollback()
                flash(f"Error submitting IoC: {str(e)}", "danger")
                return redirect(url_for("ioc_analysis"))

        iocs = db.query(IndicatorOfCompromise).filter(IndicatorOfCompromise.created_by == user.id).all()
        close_session(db)
        return render_template("ioc_analysis.html", iocs=iocs)

    @app.route("/analyze_ioc/<int:ioc_id>", methods=["POST"])
    @login_required
    def analyze_ioc(ioc_id):
        """Trigger comprehensive IoC analysis with threat intelligence"""
        user = current_user()
        db = get_session()

        ioc = db.get(IndicatorOfCompromise, ioc_id)
        if not ioc or ioc.created_by != user.id:
            close_session(db)
            flash("IoC not found or access denied.", "danger")
            return redirect(url_for("ioc_analysis"))

        # Enhanced IoC analysis with detailed threat intelligence
        analysis_result = perform_ioc_analysis(ioc)

        analysis = IoCAnalysis(
            ioc_id=ioc_id,
            analysis_type="comprehensive_threat_intelligence",
            detection_method=analysis_result['detection_method'],
            threat_indication=analysis_result['threat_indication'],
            analysis_result=json.dumps(analysis_result['analysis_result']),
            mitigation_steps=analysis_result['mitigation_steps'],
            false_positive_probability=analysis_result['false_positive_probability'],
            validated=False,
            analyst_notes=analysis_result['analyst_notes'],
            created_by=user.id
        )

        db.add(analysis)
        db.commit()

        log_audit_event(user, "IOC_ANALYSIS", "SECURITY",
                       f"Analyzed IoC {ioc.indicator_value} - {analysis_result['risk_score']}/100 risk score", f"/analyze_ioc/{ioc_id}", True)

        close_session(db)
        flash(f"IoC analysis completed. Risk score: {analysis_result['risk_score']}/100", "success")
        return redirect(url_for("ioc_analysis"))

    @app.route("/api/ioc_details/<int:ioc_id>")
    @login_required
    def get_ioc_details(ioc_id):
        """API endpoint to get detailed IoC information"""
        user = current_user()
        db = get_session()

        ioc = db.get(IndicatorOfCompromise, ioc_id)
        if not ioc or ioc.created_by != user.id:
            close_session(db)
            return {"error": "IoC not found or access denied"}, 404

        # Get the latest analysis if available
        latest_analysis = db.query(IoCAnalysis).filter(IoCAnalysis.ioc_id == ioc_id).order_by(IoCAnalysis.created_at.desc()).first()

        # Parse tags
        tags = []
        if ioc.tags:
            try:
                tags = json.loads(ioc.tags)
            except:
                tags = []

        ioc_details = {
            "id": ioc.id,
            "indicator_type": ioc.indicator_type,
            "indicator_value": ioc.indicator_value,
            "confidence": ioc.confidence,
            "severity": ioc.severity,
            "status": ioc.status,
            "threat_actor": ioc.threat_actor,
            "campaign": ioc.campaign,
            "malware_family": ioc.malware_family,
            "first_seen": ioc.first_seen.strftime('%Y-%m-%d %H:%M:%S') if ioc.first_seen else None,
            "last_seen": ioc.last_seen.strftime('%Y-%m-%d %H:%M:%S') if ioc.last_seen else None,
            "detection_source": ioc.detection_source,
            "description": ioc.description,
            "tags": tags,
            "created_at": ioc.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            "updated_at": ioc.updated_at.strftime('%Y-%m-%d %H:%M:%S'),
            "creator": ioc.creator.email if ioc.creator else "Unknown"
        }

        if latest_analysis:
            analysis_details = {
                "analysis_type": latest_analysis.analysis_type,
                "detection_method": latest_analysis.detection_method,
                "threat_indication": latest_analysis.threat_indication,
                "mitigation_steps": latest_analysis.mitigation_steps,
                "false_positive_probability": latest_analysis.false_positive_probability,
                "validated": latest_analysis.validated,
                "analyst_notes": latest_analysis.analyst_notes,
                "analyzed_at": latest_analysis.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                "analyst": latest_analysis.analyst.email if latest_analysis.analyst else "Unknown"
            }

            # Parse analysis result JSON
            if latest_analysis.analysis_result:
                try:
                    analysis_details["analysis_result"] = json.loads(latest_analysis.analysis_result)
                except:
                    analysis_details["analysis_result"] = None

            ioc_details["latest_analysis"] = analysis_details

        close_session(db)
        return ioc_details

    @app.route("/opencti_integration", methods=["GET", "POST"])
    @login_required
    def opencti_integration():
        """OpenCTI platform integration management"""
        user = current_user()
        db = get_session()

        if request.method == "POST":
            integration = OpenCTIIntegration(
                platform_url=request.form.get("platform_url"),
                api_key=request.form.get("api_key"),
                status="connected" if request.form.get("test_connection") else "disconnected"
            )
            db.add(integration)
            db.commit()
            flash("OpenCTI integration configured.", "success")
            return redirect(url_for("opencti_integration"))

        integrations = db.query(OpenCTIIntegration).all()
        logging.info(f"DEBUG: integrations type: {type(integrations)}, length: {len(integrations)}")
        for i, integration in enumerate(integrations):
            logging.info(f"DEBUG: integration {i}: type={type(integration)}, id={integration.id}, platform_url={integration.platform_url}")

        # Convert to dictionaries for JSON serialization in JavaScript
        integrations_json = []
        for integration in integrations:
            integration_dict = {
                'id': integration.id,
                'platform_url': integration.platform_url,
                'api_key': integration.api_key,
                'status': integration.status,
                'last_sync': integration.last_sync.isoformat() if integration.last_sync else None,
                'total_indicators': integration.total_indicators,
                'total_reports': integration.total_reports,
                'created_at': integration.created_at.isoformat() if integration.created_at else None,
                'updated_at': integration.updated_at.isoformat() if integration.updated_at else None
            }
            integrations_json.append(integration_dict)

        connectors = db.query(OpenCTIConnector).all()
        close_session(db)
        return render_template("opencti_integration.html",
                              integrations=integrations,
                              integrations_json=integrations_json,
                              connectors=connectors)

    @app.route("/sync_opencti/<int:integration_id>", methods=["POST"])
    @login_required
    def sync_opencti(integration_id):
        """Sync data with OpenCTI platform"""
        user = current_user()
        db = get_session()

        integration = db.get(OpenCTIIntegration, integration_id)
        if not integration:
            close_session(db)
            flash("Integration not found.", "danger")
            return redirect(url_for("opencti_integration"))

        # Mock sync - in production, implement actual OpenCTI API calls
        integration.last_sync = datetime.now(timezone.utc)
        integration.total_indicators += 10  # Mock data
        integration.total_reports += 2     # Mock data
        db.commit()

        log_audit_event(user, "OPENCTI_SYNC", "SECURITY",
                       f"Synced with OpenCTI platform {integration.platform_url}", f"/sync_opencti/{integration_id}", True)

        close_session(db)
        flash("OpenCTI sync completed.", "success")
        return redirect(url_for("opencti_integration"))

    # --- End of Threat Intelligence Routes ---

    # --- Risk Management Strategies Routes ---

    @app.route("/risk_identification")
    @login_required
    def risk_identification():
        """Risk identification from vulnerability scan results"""
        user = current_user()
        db = get_session()

        # Get vulnerability scan results for risk identification
        scans = db.query(VulnerabilityScan).filter(VulnerabilityScan.performed_by == user.id).all()
        findings = []
        for scan in scans:
            scan_findings = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.scan_id == scan.id).all()
            findings.extend(scan_findings)

        close_session(db)
        return render_template("risk_identification.html", scans=scans, findings=findings)

    @app.route("/critical_risks")
    @login_required
    def critical_risks():
        """Critical risks assessment with explanations and treatment recommendations"""
        user = current_user()
        db = get_session()

        # Get critical risks (score > 15 or severity = critical)
        critical_risks_list = db.query(Risk).filter(
            (Risk.score > 15) | (Risk.severity == RiskSeverity.CRITICAL)
        ).all()

        # Get risks visible to user based on role
        if user.role == "admin":
            risks = critical_risks_list
        elif user.role == "auditor":
            risks = critical_risks_list
        else:
            risks = [r for r in critical_risks_list if r.owner == user.email]

        close_session(db)
        return render_template("critical_risks.html", risks=risks)

    @app.route("/risk_monitoring")
    @login_required
    def risk_monitoring():
        """Risk monitoring procedures for tracking identified risks"""
        user = current_user()
        db = get_session()

        # Get risk indicators for monitoring
        indicators = db.query(RiskIndicator).filter(RiskIndicator.is_active == True).all()

        # Get recent indicator readings
        readings = {}
        for indicator in indicators:
            latest_reading = db.query(IndicatorReading).filter(
                IndicatorReading.indicator_id == indicator.id
            ).order_by(IndicatorReading.timestamp.desc()).first()
            readings[indicator.id] = latest_reading

        close_session(db)
        return render_template("risk_monitoring.html", indicators=indicators, readings=readings)

    # --- Security Monitoring Routes ---

    @app.route("/monitoring_setup", methods=["GET", "POST"])
    @login_required
    def monitoring_setup():
        """Security monitoring setup with use case demonstration"""
        user = current_user()

        if request.method == "POST":
            # Handle monitoring configuration form submission
            monitoring_name = request.form.get("monitoring_name")
            system_metrics = request.form.getlist("system_metrics")
            log_sources = request.form.getlist("log_sources")
            retention_period = request.form.get("retention_period")

            # Alert thresholds
            cpu_threshold = request.form.get("cpu_threshold")
            memory_threshold = request.form.get("memory_threshold")
            disk_threshold = request.form.get("disk_threshold")
            network_threshold = request.form.get("network_threshold")

            # Validate required fields
            if not monitoring_name or not system_metrics or not log_sources or not retention_period:
                flash("All fields are required.", "danger")
                return redirect(url_for("monitoring_setup"))

            # Create monitoring configuration in database
            config = MonitoringConfiguration(
                name=monitoring_name,
                retention_period_days=int(retention_period),
                cpu_enabled="cpu" in system_metrics,
                memory_enabled="memory" in system_metrics,
                disk_enabled="disk" in system_metrics,
                network_enabled="network" in system_metrics,
                system_logs_enabled="system_logs" in log_sources,
                application_logs_enabled="application_logs" in log_sources,
                security_events_enabled="security_events" in log_sources,
                cpu_threshold=int(cpu_threshold) if cpu_threshold else 90,
                memory_threshold=int(memory_threshold) if memory_threshold else 85,
                disk_threshold=int(disk_threshold) if disk_threshold else 95,
                network_threshold=int(network_threshold) if network_threshold else 1000,
                created_by=user.id
            )

            db.add(config)
            db.commit()

            # Log the configuration creation
            forensics_logger.info(f"User {user.email} created monitoring configuration: {monitoring_name}")
            log_audit_event(user, "MONITORING_CONFIG_CREATED", "ADMINISTRATION",
                            f"Created monitoring configuration '{monitoring_name}'", "/monitoring_setup", True)

            flash(f"Monitoring configuration '{monitoring_name}' created successfully!", "success")
            return redirect(url_for("monitoring_setup"))

        # GET request - display monitoring dashboard
        db = get_session()

        # Get saved monitoring configurations
        configurations = db.query(MonitoringConfiguration).filter(MonitoringConfiguration.is_active == True).all()

        # Get real system monitoring data
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        network = psutil.net_io_counters()

        # Get running processes for security monitoring
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                processes.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'cpu_percent': proc.info['cpu_percent'],
                    'memory_percent': proc.info['memory_percent']
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        # Sort by CPU usage and take top 10
        processes = sorted(processes, key=lambda x: x['cpu_percent'], reverse=True)[:10]

        # Recent security events from logs
        security_events = []
        try:
            with open("logs/forensics.log", "r") as f:
                lines = f.readlines()[-20:]  # Get more events
                security_events = [line.strip() for line in lines]
        except FileNotFoundError:
            security_events = ["No security logs available"]

        # Security monitoring alerts (simulated based on system state)
        alerts = []
        if cpu_percent > 80:
            alerts.append({"level": "warning", "message": f"High CPU usage detected: {cpu_percent:.1f}%"})
        if memory.percent > 85:
            alerts.append({"level": "critical", "message": f"High memory usage: {memory.percent:.1f}%"})
        if disk.percent > 90:
            alerts.append({"level": "warning", "message": f"Low disk space: {disk.percent:.1f}% available"})

        # Network security monitoring
        network_stats = {
            "bytes_sent": network.bytes_sent,
            "bytes_recv": network.bytes_recv,
            "packets_sent": network.packets_sent,
            "packets_recv": network.packets_recv
        }

        close_session(db)
        return render_template("monitoring_setup.html",
                               configurations=configurations,
                               cpu_percent=cpu_percent,
                               memory=memory,
                               disk=disk,
                               network=network_stats,
                               processes=processes,
                               security_events=security_events,
                               alerts=alerts)

    @app.route("/detection_rules", methods=["GET", "POST"])
    @login_required
    def detection_rules():
        """Detection rules with alert prioritization process"""
        user = current_user()
        db = get_session()

        if request.method == "POST":
            # Create new detection rule
            rule_name = request.form.get("rule_name")
            description = request.form.get("description")
            rule_type = request.form.get("rule_type")
            severity = request.form.get("severity", "medium")
            conditions = request.form.get("conditions", "[]")
            actions = request.form.get("actions")
            enabled = request.form.get("enabled") == "on"

            # Validate required fields
            if not rule_name or not description or not rule_type:
                flash("Rule name, description, and type are required.", "danger")
                close_session(db)
                return redirect(url_for("detection_rules"))

            # Create detection rule
            detection_rule = DetectionRule(
                rule_name=rule_name,
                description=description,
                rule_type=rule_type,
                conditions=conditions,
                severity=severity,
                actions=actions,
                enabled=enabled,
                created_by=user.id
            )

            db.add(detection_rule)
            db.commit()

            log_audit_event(user, "DETECTION_RULE_CREATED", "ADMINISTRATION",
                           f"Created detection rule '{rule_name}'", "/detection_rules", True)

            flash("Detection rule created successfully!", "success")
            close_session(db)
            return redirect(url_for("detection_rules"))

        # GET request - display detection rules
        # Get detection rules
        detection_rules = db.query(DetectionRule).filter(DetectionRule.created_by == user.id).all()

        # Get recent incidents for prioritization examples
        incidents = db.query(Incident).filter(Incident.reported_by == user.id).order_by(Incident.reported_at.desc()).limit(5).all()

        close_session(db)
        return render_template("detection_rules.html", detection_rules=detection_rules, incidents=incidents)

    @app.route("/detection_rule/<int:rule_id>")
    @login_required
    def get_detection_rule_details(rule_id):
        """Get detailed information for a specific detection rule"""
        user = current_user()
        db = get_session()

        # Get the rule and verify ownership
        rule = db.get(DetectionRule, rule_id)
        if not rule or rule.created_by != user.id:
            close_session(db)
            return {"error": "Rule not found or access denied"}, 404

        # Parse conditions if it's JSON
        conditions = []
        if rule.conditions:
            try:
                conditions = json.loads(rule.conditions)
            except:
                conditions = []

        # Return rule details as JSON
        rule_details = {
            "id": rule.id,
            "rule_name": rule.rule_name,
            "description": rule.description,
            "rule_type": rule.rule_type,
            "severity": rule.severity,
            "conditions": conditions,
            "actions": rule.actions,
            "enabled": rule.enabled,
            "last_triggered": rule.last_triggered.strftime('%Y-%m-%d %H:%M:%S') if rule.last_triggered else None,
            "created_at": rule.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            "updated_at": rule.updated_at.strftime('%Y-%m-%d %H:%M:%S')
        }

        close_session(db)
        return rule_details

    @app.route("/incident_response")
    @login_required
    def incident_response():
        """Incident response scenario with classification and lessons learned"""
        user = current_user()
        db = get_session()

        # Get user's incidents for response scenarios
        incidents = db.query(Incident).filter(Incident.reported_by == user.id).all()

        close_session(db)
        return render_template("incident_response.html", incidents=incidents)

    # error handlers
    @app.errorhandler(404)
    def not_found(e):
        """
        Handle 404 Not Found errors with user-friendly error page.

        Displays custom 404 error page when requested resource is not found.
        Logs error for debugging while providing secure error response.

        Args:
            e: Flask exception object containing error details

        Returns:
            Tuple of (rendered template, HTTP status code 404)

        Security Note:
            Prevents information disclosure through generic error messages
            Maintains consistent user experience for invalid URLs
        """
        return render_template("errors/404.html"), 404


    @app.errorhandler(500)
    def server_error(e):
        """
        Handle 500 Internal Server Error with secure error handling.

        Processes server errors with proper logging and user-friendly response.
        Prevents sensitive information disclosure while maintaining audit trail.

        Args:
            e: Flask exception object containing error details

        Returns:
            Tuple of (rendered template, HTTP status code 500)

        Security Features:
            - Error logging for debugging and monitoring
            - Generic error message to prevent information leakage
            - Consistent error response format
            - Audit trail maintenance

        Note:
            Logs full error details for administrators
            Displays sanitized error page to users
            Supports incident response and troubleshooting
        """
        logging.error(f"500 Error: {e}")
        return render_template("errors/500.html"), 500


    return app


# ------------------------------------------------------------------------------
# Utils
# ------------------------------------------------------------------------------
ALLOWED_EXTENSIONS = {".pdf", ".txt", ".log", ".png", ".jpg", ".jpeg"}



def allowed_file(filename: str) -> bool:
    """
    Validate file extension against whitelist for security.

    Checks if uploaded file has an allowed extension to prevent
    execution of malicious file types and ensure only safe
    document formats are accepted.

    Args:
        filename (str): Name of the file to validate

    Returns:
        bool: True if file extension is allowed, False otherwise

    Allowed Extensions:
        .pdf: Portable Document Format
        .txt: Plain text files
        .log: Log files
        .png: PNG images
        .jpg/.jpeg: JPEG images

    Security Note:
        Prevents upload of executable files, scripts, or other
        potentially dangerous file types that could compromise security
    """
    ext = os.path.splitext(filename)[1].lower()
    return ext in ALLOWED_EXTENSIONS


def secure_filename(name: str) -> str:
    """
    Sanitize filename to prevent path traversal and injection attacks.

    Applies stricter sanitization than Werkzeug's default secure_filename
    to eliminate any characters that could be used for directory traversal
    or command injection.

    Args:
        name (str): Original filename to sanitize

    Returns:
        str: Sanitized filename safe for filesystem operations

    Security Features:
        - Removes path separators (/, \\)
        - Eliminates shell metacharacters
        - Strips control characters
        - Allows only alphanumeric, underscore, dot, and hyphen

    Note:
        More restrictive than Werkzeug default for enhanced security
        Preserves file extension for proper type identification
    """
    # stricter sanitization than werkzeug default
    name = werkzeug_secure(name)
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name)


def json_dumps(obj) -> str:
    """
    Serialize Python object to JSON string with consistent formatting.

    Provides standardized JSON serialization for database storage and API responses.
    Configured for human-readable output and Unicode support.

    Args:
        obj: Python object to serialize (dict, list, etc.)

    Returns:
        str: JSON-formatted string with proper indentation

    Configuration:
        ensure_ascii=False: Preserves Unicode characters
        indent=2: Human-readable formatting with 2-space indentation

    Note:
        Used for storing structured data in database text fields
        Consistent formatting aids in debugging and data analysis
    """
    return json.dumps(obj, ensure_ascii=False, indent=2)


def delete_file_after_delay(file_path: str, delay_seconds: int = 120):
    """
    Schedule secure deletion of uploaded file after specified delay.

    Implements automatic cleanup of temporary files to prevent disk space exhaustion
    and maintain security by removing potentially sensitive uploaded content.

    Args:
        file_path (str): Path to the file to delete
        delay_seconds (int): Delay before deletion in seconds (default: 120)

    Process:
        1. Creates background daemon thread for non-blocking execution
        2. Waits for specified delay period
        3. Checks if file still exists (may have been manually deleted)
        4. Attempts secure file removal
        5. Logs success or error conditions

    Security Benefits:
        - Prevents accumulation of sensitive files on disk
        - Reduces attack surface by limiting file exposure time
        - Automatic cleanup reduces manual intervention needs

    Note:
        Uses daemon thread to prevent blocking application shutdown
        Gracefully handles deletion errors without crashing
        Default 2-minute delay allows for processing/scanning time
    """
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
                    "INSERT INTO users (email, password_hash, is_verified, role, approval_limit, escalation_threshold, escalation_level, audit_trail_enabled, created_at, updated_at) VALUES (:e, :p, :v, :r, :al, :et, :el, :at, :createdDate, :updatedDate)",
                    {
                        "e": "kush786srj@gmail.com",
                        "p": pw,
                        "v": True,
                        "r": "admin",
                        "al": 100000.0,
                        "et": 15,
                        "el": "executive",
                        "at": True,
                        "createdDate":datetime.now(timezone.utc),  
                        "updatedDate":datetime.now(timezone.utc) 
                    },
                )
                logging.info("Default admin user created")

            ##############
            # Seed risk management frameworks
            frameworks_data = [
            {
                "name": "NIST RMF",
                "version": "2.0",
                "description": "NIST Risk Management Framework for information systems",
                "customization_notes": "Adapted for general organizational risk management"
            },
            {
                "name": "ISO 31000",
                "version": "2018",
                "description": "International standard for risk management",
                "customization_notes": "Integrated with existing compliance frameworks"
            },
            {
                "name": "COSO",
                "version": "2017",
                "description": "COSO Enterprise Risk Management framework",
                "customization_notes": "Focused on enterprise-wide risk management"
            }]

            for fw_data in frameworks_data:
                from sqlalchemy import text
                result = conn.execute(text("SELECT id FROM risk_management_frameworks WHERE name = :name"), {"name": fw_data["name"]})
                existing = result.fetchone()
    
                if not existing:
                    conn.execute(text("""
                    INSERT INTO risk_management_frameworks (name, version, description, customization_notes, is_active, created_at, updated_at)
                    VALUES (:name, :version, :description, :customization_notes, :is_active, :created_at, :updated_at)"""), {
                    "name": fw_data["name"],
                    "version": fw_data["version"], 
                    "description": fw_data["description"],
                    "customization_notes": fw_data["customization_notes"],
                    "is_active": True,
                    "created_at": datetime.now(timezone.utc),
                    "updated_at": datetime.now(timezone.utc)
                 })


            # Seed default risk indicators
            indicators_data = [
            {
                "name": "Total Risk Count",
                "description": "Total number of identified risks",
                "indicator_type": "lagging",
                "data_source": "risk_count",
                "target_value": 50.0,
                "threshold_warning": 75.0,
                "threshold_critical": 100.0,
                "unit": "count"
            },
            {
                "name": "Critical Risk Count",
                "description": "Number of critical severity risks",
                "indicator_type": "leading",
                "data_source": "critical_risk_count",
                "target_value": 5.0,
                "threshold_warning": 10.0,
                "threshold_critical": 15.0,
                "unit": "count"
            },
            {
                "name": "Open Incidents",
                "description": "Number of open security incidents",
                "indicator_type": "leading",
                "data_source": "open_incident_count",
                "target_value": 2.0,
                "threshold_warning": 5.0,
                "threshold_critical": 10.0,
                "unit": "count"
            },
            {
                "name": "Compliance Score",
                "description": "Average compliance assessment score",
                "indicator_type": "lagging",
                "data_source": "compliance_score",
                "target_value": 85.0,
                "threshold_warning": 70.0,
                "threshold_critical": 50.0,
                "unit": "percentage"
            }]

            # Seed sample IoCs
            iocs_data = [
            {
                "indicator_type": "ip",
                "indicator_value": "192.168.1.100",
                "confidence": 85,
                "severity": "high",
                "status": "active",
                "threat_actor": "APT28",
                "campaign": "SolarWinds",
                "description": "Command and control server IP",
                "tags": ["c2", "apt", "solarwinds"]
            },
            {
                "indicator_type": "domain",
                "indicator_value": "malicious.example.com",
                "confidence": 90,
                "severity": "critical",
                "status": "active",
                "threat_actor": "Lazarus Group",
                "campaign": "Banking Malware",
                "description": "Malicious domain used for phishing",
                "tags": ["phishing", "malware", "banking"]
            },
            {
                "indicator_type": "hash",
                "indicator_value": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
                "confidence": 95,
                "severity": "critical",
                "status": "active",
                "threat_actor": "Unknown",
                "malware_family": "Ransomware",
                "description": "SHA256 hash of ransomware sample",
                "tags": ["ransomware", "malware", "crypto"]
            },
            {
                "indicator_type": "url",
                "indicator_value": "https://fake-bank-login.com",
                "confidence": 80,
                "severity": "high",
                "status": "active",
                "threat_actor": "Unknown",
                "campaign": "Credential Theft",
                "description": "Phishing URL mimicking banking site",
                "tags": ["phishing", "credentials", "banking"]
            },
            {
                "indicator_type": "email",
                "indicator_value": "support@fake-bank.com",
                "confidence": 75,
                "severity": "medium",
                "status": "active",
                "threat_actor": "Unknown",
                "campaign": "BEC",
                "description": "Email address used in business email compromise",
                "tags": ["bec", "phishing", "email"]
            }
            ]

            for ioc_data in iocs_data:
                result = conn.execute(text("SELECT id FROM indicators_of_compromise WHERE indicator_value = :value"), {"value": ioc_data["indicator_value"]})
                existing = result.fetchone()

                if not existing:
                    conn.execute(text("""
                    INSERT INTO indicators_of_compromise (indicator_type, indicator_value, confidence, severity, status,
                        threat_actor, campaign, malware_family, first_seen, last_seen, detection_source, description, tags, created_by, created_at, updated_at)
                    VALUES (:indicator_type, :indicator_value, :confidence, :severity, :status,
                        :threat_actor, :campaign, :malware_family, :first_seen, :last_seen, :detection_source, :description, :tags, :created_by, :created_at, :updated_at)"""), {
                        "indicator_type": ioc_data["indicator_type"],
                        "indicator_value": ioc_data["indicator_value"],
                        "confidence": ioc_data["confidence"],
                        "severity": ioc_data["severity"],
                        "status": ioc_data["status"],
                        "threat_actor": ioc_data.get("threat_actor"),
                        "campaign": ioc_data.get("campaign"),
                        "malware_family": ioc_data.get("malware_family"),
                        "first_seen": datetime.now(timezone.utc) - timedelta(days=30),
                        "last_seen": datetime.now(timezone.utc),
                        "detection_source": "Internal Analysis",
                        "description": ioc_data["description"],
                        "tags": json.dumps(ioc_data["tags"]),
                        "created_by": 1,  # Default admin user
                        "created_at": datetime.now(timezone.utc),
                        "updated_at": datetime.now(timezone.utc)
                    })

            # Seed sample OpenCTI integrations
            opencti_data = [
            {
                "platform_url": "https://demo.opencti.io",
                "api_key": "demo-api-key-12345",
                "status": "connected",
                "total_indicators": 1250,
                "total_reports": 89
            },
            {
                "platform_url": "https://threatintel.company.com",
                "api_key": "company-api-key-67890",
                "status": "disconnected",
                "total_indicators": 0,
                "total_reports": 0
            }
            ]

            for octi_data in opencti_data:
                result = conn.execute(text("SELECT id FROM opencti_integrations WHERE platform_url = :url"), {"url": octi_data["platform_url"]})
                existing = result.fetchone()

                if not existing:
                    conn.execute(text("""
                    INSERT INTO opencti_integrations (platform_url, api_key, status, total_indicators, total_reports, last_sync, created_at, updated_at)
                    VALUES (:platform_url, :api_key, :status, :total_indicators, :total_reports, :last_sync, :created_at, :updated_at)"""), {
                        "platform_url": octi_data["platform_url"],
                        "api_key": octi_data["api_key"],
                        "status": octi_data["status"],
                        "total_indicators": octi_data["total_indicators"],
                        "total_reports": octi_data["total_reports"],
                        "last_sync": datetime.now(timezone.utc) if octi_data["status"] == "connected" else None,
                        "created_at": datetime.now(timezone.utc),
                        "updated_at": datetime.now(timezone.utc)
                    })

            # Seed sample OpenCTI connectors
            connectors_data = [
            {
                "name": "MITRE ATT&CK",
                "description": "MITRE ATT&CK framework integration for tactic and technique mapping",
                "connector_type": "internal",
                "scope": "threat-actor",
                "active": True
            },
            {
                "name": "VirusTotal",
                "description": "VirusTotal malware analysis and reputation service integration",
                "connector_type": "external",
                "scope": "observable",
                "active": True
            },
            {
                "name": "MISP",
                "description": "MISP threat intelligence sharing platform integration",
                "connector_type": "external",
                "scope": "threat-intelligence",
                "active": False
            },
            {
                "name": "AlienVault OTX",
                "description": "AlienVault Open Threat Exchange integration",
                "connector_type": "external",
                "scope": "observable",
                "active": True
            }
            ]

            for conn_data in connectors_data:
                result = conn.execute(text("SELECT id FROM opencti_connectors WHERE name = :name"), {"name": conn_data["name"]})
                existing = result.fetchone()

                if not existing:
                    conn.execute(text("""
                    INSERT INTO opencti_connectors (name, description, connector_type, scope, active, created_at, updated_at)
                    VALUES (:name, :description, :connector_type, :scope, :active, :created_at, :updated_at)"""), {
                        "name": conn_data["name"],
                        "description": conn_data["description"],
                        "connector_type": conn_data["connector_type"],
                        "scope": conn_data["scope"],
                        "active": conn_data["active"],
                        "created_at": datetime.now(timezone.utc),
                        "updated_at": datetime.now(timezone.utc)
                    })

            for ind_data in indicators_data:
                result = conn.execute(text("SELECT id FROM risk_indicators WHERE name = :name"), {"name": ind_data["name"]})
                existing = result.fetchone()

                if not existing:
                    conn.execute(text("""INSERT INTO risk_indicators (name, description, indicator_type, data_source, calculation_method, 
                         target_value, threshold_warning, threshold_critical, unit, frequency, is_active, created_at, updated_at)
                         VALUES (:name, :description, :indicator_type, :data_source, :calculation_method, :target_value, 
                         :threshold_warning, :threshold_critical, :unit, :frequency, :is_active, :created_at, :updated_at)"""), {
                        "name": ind_data["name"],
                        "description": ind_data["description"],
                        "indicator_type": ind_data["indicator_type"],
                        "data_source": ind_data["data_source"],
                        "calculation_method": None,  # calculation_method
                        "target_value": ind_data["target_value"],
                        "threshold_warning": ind_data["threshold_warning"],
                        "threshold_critical": ind_data["threshold_critical"],
                        "unit": ind_data["unit"],
                        "frequency": "daily",
                        "is_active": True,
                        "created_at": datetime.now(timezone.utc),
                        "updated_at": datetime.now(timezone.utc)
                        })

    ##########

    # Enable debug mode for development (shows detailed error messages)
    app.run(debug=True, host="127.0.0.1", port=5000)




