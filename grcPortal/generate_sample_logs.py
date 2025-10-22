#!/usr/bin/env python3
"""
Script to generate comprehensive sample log data for testing the GRC Portal monitoring functionality.

This script creates realistic log entries that demonstrate:
1. Authentication events (successful/failed logins)
2. File access events (authorized/unauthorized access)
3. Network activity (blocked connections, suspicious traffic)
4. System events (resource usage, service status)
5. Security events (malware detection, policy violations)

Usage: python generate_sample_logs.py
"""

import json
import random
from datetime import datetime, timedelta, timezone

def generate_sample_logs():
    """Generate comprehensive sample log data for testing"""

    # Base timestamp
    base_time = datetime.now(timezone.utc) - timedelta(hours=24)

    sample_logs = []

    # 1. Authentication Logs (Windows Event Logs style)
    auth_logs = [
        f"{(base_time + timedelta(minutes=0)).isoformat()} info User login successful: administrator from 192.168.1.100",
        f"{(base_time + timedelta(minutes=15)).isoformat()} warning Failed login attempt for user: administrator from 192.168.1.100",
        f"{(base_time + timedelta(minutes=16)).isoformat()} warning Failed login attempt for user: administrator from 192.168.1.100",
        f"{(base_time + timedelta(minutes=17)).isoformat()} warning Failed login attempt for user: administrator from 192.168.1.100",
        f"{(base_time + timedelta(minutes=18)).isoformat()} error Account locked due to too many failed attempts: administrator",
        f"{(base_time + timedelta(minutes=30)).isoformat()} info User login successful: auditor from 192.168.1.101",
        f"{(base_time + timedelta(minutes=45)).isoformat()} info User logout: administrator",
        f"{(base_time + timedelta(minutes=60)).isoformat()} warning Suspicious login pattern detected for user: administrator",
        f"{(base_time + timedelta(minutes=75)).isoformat()} info User login successful: security_admin from 192.168.1.102",
        f"{(base_time + timedelta(minutes=90)).isoformat()} info Password changed for user: administrator",
    ]

    # 2. File Access Logs (Linux audit logs style)
    file_logs = [
        f"{(base_time + timedelta(minutes=5)).isoformat()} warning Suspicious file access attempt: /etc/passwd by user www-data",
        f"{(base_time + timedelta(minutes=10)).isoformat()} info File accessed: /var/log/auth.log by user root",
        f"{(base_time + timedelta(minutes=20)).isoformat()} warning Unauthorized access to sensitive file: /etc/shadow by user apache",
        f"{(base_time + timedelta(minutes=35)).isoformat()} info File modified: /etc/apache2/apache2.conf by user root",
        f"{(base_time + timedelta(minutes=50)).isoformat()} warning Permission denied: /root/.ssh/authorized_keys access by user www-data",
        f"{(base_time + timedelta(minutes=65)).isoformat()} info File created: /tmp/suspicious_script.sh by user unknown",
        f"{(base_time + timedelta(minutes=80)).isoformat()} error File access blocked: /etc/sudoers by user regular_user",
        f"{(base_time + timedelta(minutes=95)).isoformat()} warning Unusual file access pattern: multiple /etc/ files accessed by user mysql",
    ]

    # 3. Network Activity Logs (Firewall logs style)
    network_logs = [
        f"{(base_time + timedelta(minutes=2)).isoformat()} error Firewall blocked inbound connection from 203.0.113.1:443 to 192.168.1.100:80",
        f"{(base_time + timedelta(minutes=8)).isoformat()} warning Unusual network traffic detected: 500 connections/minute from 192.168.1.50",
        f"{(base_time + timedelta(minutes=12)).isoformat()} info IDS alert: SQL injection attempt blocked from 198.51.100.1",
        f"{(base_time + timedelta(minutes=25)).isoformat()} error Firewall blocked outbound connection to known C2 server: 203.0.113.195:443",
        f"{(base_time + timedelta(minutes=40)).isoformat()} warning Port scan detected from 192.0.2.100 targeting ports 1-1024",
        f"{(base_time + timedelta(minutes=55)).isoformat()} info VPN connection established: user remote_worker from 10.0.0.5",
        f"{(base_time + timedelta(minutes=70)).isoformat()} error SSL certificate validation failed for connection to api.malicious.com",
        f"{(base_time + timedelta(minutes=85)).isoformat()} warning High bandwidth usage detected: 950 Mbps outbound traffic",
    ]

    # 4. System Performance Logs
    system_logs = [
        f"{(base_time + timedelta(minutes=1)).isoformat()} info System startup completed successfully - uptime: 0 days",
        f"{(base_time + timedelta(minutes=3)).isoformat()} warning High CPU usage detected: 95% utilization on core 0",
        f"{(base_time + timedelta(minutes=6)).isoformat()} error Service failed to start: apache2 - connection refused on port 80",
        f"{(base_time + timedelta(minutes=9)).isoformat()} info Disk space check: 75% used (15GB free on /)",
        f"{(base_time + timedelta(minutes=13)).isoformat()} warning Memory usage high: 88% of 8GB used",
        f"{(base_time + timedelta(minutes=22)).isoformat()} info System update completed: kernel patched to version 5.4.0-74",
        f"{(base_time + timedelta(minutes=28)).isoformat()} error Database connection timeout: retrying in 30 seconds",
        f"{(base_time + timedelta(minutes=33)).isoformat()} info Backup completed successfully: 2.3GB archived to /backup",
        f"{(base_time + timedelta(minutes=38)).isoformat()} warning RAID array degraded: disk /dev/sdb failed",
        f"{(base_time + timedelta(minutes=42)).isoformat()} info Load balancer health check passed for all nodes",
    ]

    # 5. Security Events (Advanced threats)
    security_logs = [
        f"{(base_time + timedelta(minutes=4)).isoformat()} critical Malware signature detected: trojan.exe (SHA256: a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3)",
        f"{(base_time + timedelta(minutes=11)).isoformat()} warning Privilege escalation attempt detected: user apache attempted to gain root privileges",
        f"{(base_time + timedelta(minutes=19)).isoformat()} error Unauthorized SSH access attempt from 198.51.100.1 using brute force",
        f"{(base_time + timedelta(minutes=27)).isoformat()} info Security scan completed: 3 vulnerabilities found (2 high, 1 medium)",
        f"{(base_time + timedelta(minutes=31)).isoformat()} warning Suspicious process detected: unknown binary executing from /tmp/",
        f"{(base_time + timedelta(minutes=44)).isoformat()} error Data exfiltration attempt blocked: large outbound transfer to external IP",
        f"{(base_time + timedelta(minutes=52)).isoformat()} info Endpoint protection updated: 150 new signatures added",
        f"{(base_time + timedelta(minutes=67)).isoformat()} warning Configuration change detected: firewall rules modified by unauthorized user",
        f"{(base_time + timedelta(minutes=73)).isoformat()} error API rate limit exceeded: 1000 requests/minute from single IP",
        f"{(base_time + timedelta(minutes=89)).isoformat()} critical Ransomware behavior detected: file encryption pattern observed",
    ]

    # Combine all logs
    all_logs = auth_logs + file_logs + network_logs + system_logs + security_logs

    # Create formatted output
    print("COMPREHENSIVE SAMPLE LOG DATA FOR GRC PORTAL TESTING")
    print("=" * 60)
    print()
    print("Copy and paste the log data below into the 'Bulk Log Upload' section")
    print("of the Add Log Data page (/add_log_data) in your GRC Portal.")
    print()
    print("Source Name: comprehensive_security_logs")
    print()
    print("LOG DATA:")
    print("-" * 40)

    for log in all_logs:
        print(log)

    print()
    print("=" * 60)
    print(f"Total sample logs generated: {len(all_logs)}")
    print()
    print("LOG BREAKDOWN:")
    print(f"- Authentication logs: {len(auth_logs)}")
    print(f"- File access logs: {len(file_logs)}")
    print(f"- Network activity logs: {len(network_logs)}")
    print(f"- System performance logs: {len(system_logs)}")
    print(f"- Security events: {len(security_logs)}")
    print()
    print("EXPECTED ALERTS:")
    print("- Multiple failed login attempts should trigger authentication alerts")
    print("- Suspicious file access should trigger file access alerts")
    print("- Blocked connections should trigger network alerts")
    print("- High resource usage should trigger system alerts")
    print("- Malware detection should trigger critical security alerts")
    print()
    print("TESTING INSTRUCTIONS:")
    print("1. Start your GRC Portal application")
    print("2. Navigate to /add_log_data")
    print("3. Use 'comprehensive_security_logs' as the source name")
    print("4. Copy the log data above into the bulk upload textarea")
    print("5. Click 'Upload Bulk Logs'")
    print("6. Check the monitoring dashboard (/monitoring) for alerts")
    print("7. Verify the security event analysis page shows the new logs")

if __name__ == "__main__":
    generate_sample_logs()