#!/usr/bin/env python3
"""
Script to generate sample monitoring data for the GRC Portal security monitoring demonstration.

This script will:
1. Create default alert rules
2. Simulate log collection from Windows and Linux sources
3. Process alerts from the collected logs
4. Display summary of generated data
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import create_app, simulate_log_collection, create_default_alert_rules, process_alerts_from_logs
from models import LogSource, CollectedLog, AlertRule, Alert, MonitoringConfiguration
from db import close_session

def generate_sample_data():
    """Generate sample monitoring data for demonstration"""

    app = create_app()

    with app.app_context():
        print("Generating sample monitoring data for GRC Portal...")
        print("=" * 60)

        # Step 1: Create default alert rules
        print("\nStep 1: Creating default alert rules...")
        rules = create_default_alert_rules()
        print(f"Created {len(rules)} alert rules:")
        for rule in rules:
            print(f"   - {rule.name} ({rule.alert_severity} severity)")

        # Step 1.5: Create default monitoring configuration
        print("\nStep 1.5: Creating default monitoring configuration...")
        from db import get_session
        db = get_session()
        existing_config = db.query(MonitoringConfiguration).first()
        if not existing_config:
            config = MonitoringConfiguration(
                name="Default Enterprise Monitoring",
                retention_period_days=90,
                cpu_enabled=True,
                memory_enabled=True,
                disk_enabled=True,
                network_enabled=True,
                system_logs_enabled=True,
                application_logs_enabled=True,
                security_events_enabled=True,
                cpu_threshold=90,
                memory_threshold=85,
                disk_threshold=95,
                network_threshold=1000,
                is_active=True,
                created_by=1  # Default admin user
            )
            db.add(config)
            db.commit()
            print("Created default monitoring configuration")
        else:
            print("Monitoring configuration already exists")
        close_session(db)

        # Step 2: Simulate log collection
        print("\nStep 2: Simulating log collection...")
        log_data = simulate_log_collection()
        if log_data and 'error' not in log_data:
            print("Log collection simulation completed:")
            print(f"   - Total logs collected: {log_data['total_logs']}")

            # Get log counts by category
            from db import get_session
            db = get_session()
            auth_logs = db.query(CollectedLog).filter(CollectedLog.category == 'authentication').count()
            file_logs = db.query(CollectedLog).filter(CollectedLog.category == 'file_access').count()
            network_logs = db.query(CollectedLog).filter(CollectedLog.category == 'network_activity').count()
            print(f"   - Authentication logs: {auth_logs}")
            print(f"   - File access logs: {file_logs}")
            print(f"   - Network activity logs: {network_logs}")
            close_session(db)
        else:
            print("Log collection failed")
            return

        # Step 3: Process alerts from logs
        print("\nStep 3: Processing alerts from collected logs...")
        from db import get_session
        db = get_session()
        logs = db.query(CollectedLog).all()
        alerts = process_alerts_from_logs(logs)
        close_session(db)

        print(f"Generated {len(alerts)} alerts from log analysis")

        # Step 4: Display summary
        print("\nStep 4: Data generation summary")
        print("-" * 40)

        db = get_session()

        # Count sources
        sources = db.query(LogSource).count()
        print(f"Log Sources: {sources}")

        # Count logs by type
        total_logs = db.query(CollectedLog).count()
        windows_logs = db.query(CollectedLog).join(LogSource).filter(LogSource.source_type == 'windows').count()
        linux_logs = db.query(CollectedLog).join(LogSource).filter(LogSource.source_type == 'linux').count()
        print(f"Total Logs: {total_logs} (Windows: {windows_logs}, Linux: {linux_logs})")

        # Count alert rules
        rules_count = db.query(AlertRule).count()
        print(f"Alert Rules: {rules_count}")

        # Count alerts by severity
        total_alerts = db.query(Alert).count()
        critical_alerts = db.query(Alert).filter(Alert.severity == 'critical').count()
        high_alerts = db.query(Alert).filter(Alert.severity == 'high').count()
        medium_alerts = db.query(Alert).filter(Alert.severity == 'medium').count()
        low_alerts = db.query(Alert).filter(Alert.severity == 'low').count()
        print(f"Total Alerts: {total_alerts} (Critical: {critical_alerts}, High: {high_alerts}, Medium: {medium_alerts}, Low: {low_alerts})")

        # Show recent alerts
        recent_alerts = db.query(Alert).order_by(Alert.created_at.desc()).limit(5).all()
        if recent_alerts:
            print("\nRecent Alerts:")
            for alert in recent_alerts:
                print(f"- {alert.title} ({alert.severity}) - {alert.created_at.strftime('%H:%M:%S')}")

        close_session(db)

        print("\nSample monitoring data generation completed!")
        print("You can now view the monitoring dashboard at /monitoring")
        print("and the monitoring setup at /monitoring_setup")

if __name__ == "__main__":
    generate_sample_data()