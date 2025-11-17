#!/usr/bin/env python3
"""
Script to populate sample data for testing advanced auditing features
"""

from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import (
    AdvancedAudit, AuditTeam, EvidenceAnalysis,
    ComplianceAnalytics, AutomatedReporting, User, Base
)
import json
import os

# Database setup
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///grc_portal.db')
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def create_sample_audits(db):
    """Create sample advanced audits"""
    sample_audits = [
        {
            "audit_title": "Q4 2024 Enterprise Compliance Audit",
            "audit_type": "integrated",
            "description": "Comprehensive audit covering IT, operational, and financial compliance across 5 global sites",
            "planned_start_date": datetime(2024, 11, 1),
            "planned_end_date": datetime(2024, 12, 15),
            "lead_auditor_id": 1,
            "audit_budget": 150000.00,
            "scope_frameworks": json.dumps(["NIST SP 800-53", "ISO 27001", "GDPR", "SOX"]),
            "audit_sites": json.dumps(["New York HQ", "London Office", "Singapore DC", "Tokyo Branch", "Sydney Office"]),
            "status": "in_progress",
            "progress_percentage": 35.0,
            "current_phase": "fieldwork"
        },
        {
            "audit_title": "Data Privacy Compliance Review",
            "audit_type": "compliance",
            "description": "Focused audit on GDPR and CCPA compliance requirements",
            "planned_start_date": datetime(2024, 12, 1),
            "planned_end_date": datetime(2024, 12, 31),
            "lead_auditor_id": 1,
            "audit_budget": 75000.00,
            "scope_frameworks": json.dumps(["GDPR", "CCPA"]),
            "audit_sites": json.dumps(["New York HQ", "California Office"]),
            "status": "planned",
            "progress_percentage": 0.0,
            "current_phase": "planning"
        }
    ]

    audits = []
    for audit_data in sample_audits:
        audit = AdvancedAudit(**audit_data)
        db.add(audit)
        audits.append(audit)

    db.commit()
    return audits

def create_sample_audit_teams(db, audits):
    """Create sample audit team members"""
    if not audits:
        return

    audit_id = audits[0].id
    sample_teams = [
        {
            "audit_id": audit_id,
            "team_member_id": 1,
            "role_in_audit": "lead_auditor",
            "expertise_areas": json.dumps(["IT Security", "Risk Management", "Compliance Frameworks"]),
            "certifications": json.dumps(["CISSP", "CISA", "CRISC"]),
            "time_allocation": 1.0,
            "assigned_sites": json.dumps(["New York HQ", "London Office"])
        },
        {
            "audit_id": audit_id,
            "team_member_id": 2,
            "role_in_audit": "it_auditor",
            "expertise_areas": json.dumps(["Network Security", "Access Controls", "Incident Response"]),
            "certifications": json.dumps(["CISSP", "CEH"]),
            "time_allocation": 0.8,
            "assigned_sites": json.dumps(["Singapore DC", "Tokyo Branch"])
        }
    ]

    for team_data in sample_teams:
        team = AuditTeam(**team_data)
        db.add(team)

    db.commit()

def create_sample_evidence_analyses(db, audits):
    """Create sample evidence analyses"""
    if not audits:
        return

    audit_id = audits[0].id
    sample_analyses = [
        {
            "analysis_title": "Access Control Log Analysis",
            "analysis_type": "statistical",
            "description": "Statistical analysis of access control logs to identify unusual patterns",
            "audit_id": audit_id,
            "performed_by": 1,
            "data_sources": json.dumps(["Windows Event Logs", "Linux Auth Logs", "Application Access Logs"]),
            "analysis_scope": json.dumps({"time_range": "Last 90 days", "systems": "All critical servers"}),
            "sample_size": 50000,
            "time_period": "2024-08-01 to 2024-10-31",
            "status": "completed"
        }
    ]

    for analysis_data in sample_analyses:
        analysis = EvidenceAnalysis(**analysis_data)
        db.add(analysis)

    db.commit()

def create_sample_compliance_analytics(db):
    """Create sample compliance analytics models"""
    sample_analytics = [
        {
            "analytics_name": "Compliance Violation Prediction Model",
            "analytics_type": "predictive",
            "prediction_target": "compliance_violation_risk",
            "frameworks_analyzed": json.dumps(["NIST SP 800-53", "ISO 27001", "GDPR"]),
            "data_sources": json.dumps(["Audit Findings", "Risk Assessments", "Compliance Scores"]),
            "analysis_period": "2023-01-01 to 2024-10-31",
            "created_by": 1,
            "model_accuracy": 0.87,
            "prediction_confidence": 0.82
        }
    ]

    for analytics_data in sample_analytics:
        analytics = ComplianceAnalytics(**analytics_data)
        db.add(analytics)

    db.commit()

def create_sample_automated_reports(db):
    """Create sample automated reports"""
    sample_reports = [
        {
            "report_name": "Weekly Compliance Status Report",
            "report_type": "compliance_status",
            "schedule_frequency": "weekly",
            "schedule_time": "09:00",
            "created_by": 1,
            "executive_summary": True,
            "detailed_findings": True,
            "charts_and_graphs": True,
            "recommendations": True
        }
    ]

    for report_data in sample_reports:
        report = AutomatedReporting(**report_data)
        db.add(report)

    db.commit()

def main():
    """Main function to populate all sample data"""
    db = SessionLocal()
    try:
        print("Creating sample advanced audits...")
        audits = create_sample_audits(db)

        print("Creating sample audit teams...")
        create_sample_audit_teams(db, audits)

        print("Creating sample evidence analyses...")
        create_sample_evidence_analyses(db, audits)

        print("Creating sample compliance analytics...")
        create_sample_compliance_analytics(db)

        print("Creating sample automated reports...")
        create_sample_automated_reports(db)

        print("Sample data populated successfully!")

    except Exception as e:
        print(f"Error populating sample data: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    main()