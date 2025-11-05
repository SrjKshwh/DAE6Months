#!/usr/bin/env python3
"""
Network Isolation Integration for GRC Portal IR Environment

This script integrates network isolation procedures into the GRC Portal
by providing automated network isolation during incident response.
"""

import os
import sys
import json
import logging
import subprocess
from datetime import datetime, timezone
from typing import Dict, List, Optional

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db import get_session, close_session
from models import Incident, NetworkIsolationLog

class NetworkIsolationManager:
    """Manages network isolation procedures for incident response"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.scripts_dir = os.path.join(os.path.dirname(__file__))

    def isolate_system(self, target_ip: str, incident_id: str, reason: str = "Incident Response") -> Dict[str, any]:
        """
        Isolate a system from the network during incident response

        Args:
            target_ip: IP address of the system to isolate
            incident_id: Incident identifier for tracking
            reason: Reason for isolation

        Returns:
            Dict with isolation results
        """
        self.logger.info(f"Starting network isolation for {target_ip}, incident: {incident_id}")

        results = {
            'status': 'success',
            'target_ip': target_ip,
            'incident_id': incident_id,
            'isolation_time': datetime.now(timezone.utc),
            'actions_taken': [],
            'errors': []
        }

        try:
            # Execute network isolation script
            script_path = os.path.join(self.scripts_dir, 'network_isolation_setup.sh')
            if not os.path.exists(script_path):
                raise FileNotFoundError(f"Network isolation script not found: {script_path}")

            # Run the isolation command
            cmd = ['bash', script_path, 'isolate', target_ip]
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=self.scripts_dir,
                timeout=60
            )

            if process.returncode == 0:
                results['actions_taken'].append({
                    'action': 'network_isolation',
                    'script': 'network_isolation_setup.sh',
                    'target': target_ip,
                    'output': process.stdout.strip()
                })
                self.logger.info(f"Network isolation successful for {target_ip}")
            else:
                error_msg = f"Isolation script failed: {process.stderr.strip()}"
                results['errors'].append(error_msg)
                results['status'] = 'failed'
                self.logger.error(error_msg)

            # Log the isolation action
            self._log_isolation_action(
                incident_id=incident_id,
                action_type='isolate',
                target_ip=target_ip,
                reason=reason,
                status=results['status'],
                details=results
            )

        except subprocess.TimeoutExpired:
            error_msg = f"Network isolation timed out for {target_ip}"
            results['errors'].append(error_msg)
            results['status'] = 'timeout'
            self.logger.error(error_msg)
        except Exception as e:
            error_msg = f"Network isolation failed for {target_ip}: {str(e)}"
            results['errors'].append(error_msg)
            results['status'] = 'error'
            self.logger.error(error_msg)

        return results

    def restore_system(self, target_ip: str, incident_id: str, reason: str = "Incident Resolved") -> Dict[str, any]:
        """
        Restore network connectivity for an isolated system

        Args:
            target_ip: IP address of the system to restore
            incident_id: Incident identifier for tracking
            reason: Reason for restoration

        Returns:
            Dict with restoration results
        """
        self.logger.info(f"Starting network restoration for {target_ip}, incident: {incident_id}")

        results = {
            'status': 'success',
            'target_ip': target_ip,
            'incident_id': incident_id,
            'restoration_time': datetime.now(timezone.utc),
            'actions_taken': [],
            'errors': []
        }

        try:
            # Execute network restoration script
            script_path = os.path.join(self.scripts_dir, 'network_isolation_setup.sh')
            if not os.path.exists(script_path):
                raise FileNotFoundError(f"Network isolation script not found: {script_path}")

            # Run the restoration command
            cmd = ['bash', script_path, 'restore', target_ip]
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=self.scripts_dir,
                timeout=60
            )

            if process.returncode == 0:
                results['actions_taken'].append({
                    'action': 'network_restoration',
                    'script': 'network_isolation_setup.sh',
                    'target': target_ip,
                    'output': process.stdout.strip()
                })
                self.logger.info(f"Network restoration successful for {target_ip}")
            else:
                error_msg = f"Restoration script failed: {process.stderr.strip()}"
                results['errors'].append(error_msg)
                results['status'] = 'failed'
                self.logger.error(error_msg)

            # Log the restoration action
            self._log_isolation_action(
                incident_id=incident_id,
                action_type='restore',
                target_ip=target_ip,
                reason=reason,
                status=results['status'],
                details=results
            )

        except subprocess.TimeoutExpired:
            error_msg = f"Network restoration timed out for {target_ip}"
            results['errors'].append(error_msg)
            results['status'] = 'timeout'
            self.logger.error(error_msg)
        except Exception as e:
            error_msg = f"Network restoration failed for {target_ip}: {str(e)}"
            results['errors'].append(error_msg)
            results['status'] = 'error'
            self.logger.error(error_msg)

        return results

    def get_isolation_status(self, target_ip: Optional[str] = None) -> Dict[str, any]:
        """
        Get current network isolation status

        Args:
            target_ip: Specific IP to check, or None for all

        Returns:
            Dict with isolation status information
        """
        try:
            script_path = os.path.join(self.scripts_dir, 'network_isolation_setup.sh')
            if not os.path.exists(script_path):
                return {'status': 'error', 'error': 'Isolation script not found'}

            cmd = ['bash', script_path, 'status']
            if target_ip:
                cmd.append(target_ip)

            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=self.scripts_dir,
                timeout=30
            )

            return {
                'status': 'success' if process.returncode == 0 else 'error',
                'output': process.stdout.strip(),
                'error': process.stderr.strip() if process.returncode != 0 else None
            }

        except Exception as e:
            self.logger.error(f"Failed to get isolation status: {e}")
            return {'status': 'error', 'error': str(e)}

    def setup_virtualbox_networking(self, vm_name: Optional[str] = None) -> Dict[str, any]:
        """
        Setup VirtualBox networking for IR environment

        Args:
            vm_name: Name of VM to configure, or None to just setup networks

        Returns:
            Dict with VirtualBox networking setup results
        """
        self.logger.info("Setting up VirtualBox networking for IR environment")

        results = {
            'status': 'success',
            'vm_name': vm_name,
            'setup_time': datetime.now(timezone.utc),
            'actions_taken': [],
            'errors': []
        }

        try:
            script_path = os.path.join(self.scripts_dir, 'virtualbox_network_setup.sh')
            if not os.path.exists(script_path):
                raise FileNotFoundError(f"VirtualBox setup script not found: {script_path}")

            # Run the VirtualBox setup script
            cmd = ['bash', script_path]
            if vm_name:
                cmd.append(vm_name)

            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=self.scripts_dir,
                timeout=120  # VirtualBox operations can take time
            )

            if process.returncode == 0:
                results['actions_taken'].append({
                    'action': 'virtualbox_network_setup',
                    'script': 'virtualbox_network_setup.sh',
                    'vm_name': vm_name,
                    'output': process.stdout.strip()
                })
                self.logger.info("VirtualBox networking setup successful")
            else:
                error_msg = f"VirtualBox setup script failed: {process.stderr.strip()}"
                results['errors'].append(error_msg)
                results['status'] = 'failed'
                self.logger.error(error_msg)

        except subprocess.TimeoutExpired:
            error_msg = "VirtualBox networking setup timed out"
            results['errors'].append(error_msg)
            results['status'] = 'timeout'
            self.logger.error(error_msg)
        except Exception as e:
            error_msg = f"VirtualBox networking setup failed: {str(e)}"
            results['errors'].append(error_msg)
            results['status'] = 'error'
            self.logger.error(error_msg)

        return results

    def _log_isolation_action(self, incident_id: str, action_type: str, target_ip: str,
                            reason: str, status: str, details: Dict) -> None:
        """
        Log network isolation action to database

        Args:
            incident_id: Incident identifier
            action_type: Type of action (isolate/restore)
            target_ip: Target IP address
            reason: Reason for action
            status: Action status
            details: Detailed action information
        """
        db = get_session()
        try:
            log_entry = NetworkIsolationLog(
                incident_id=incident_id,
                action_type=action_type,
                target_ip=target_ip,
                reason=reason,
                status=status,
                details=json.dumps(details),
                performed_at=datetime.now(timezone.utc)
            )
            db.add(log_entry)
            db.commit()
            self.logger.info(f"Logged {action_type} action for {target_ip} in incident {incident_id}")
        except Exception as e:
            db.rollback()
            self.logger.error(f"Failed to log isolation action: {e}")
        finally:
            close_session(db)

def isolate_incident_systems(incident_id: str) -> Dict[str, any]:
    """
    Automatically isolate systems associated with an incident

    Args:
        incident_id: Incident identifier

    Returns:
        Dict with isolation results for all affected systems
    """
    logging.info(f"Starting automated isolation for incident {incident_id}")

    results = {
        'incident_id': incident_id,
        'isolation_time': datetime.now(timezone.utc),
        'systems_isolated': [],
        'systems_failed': [],
        'overall_status': 'success'
    }

    db = get_session()
    try:
        # Get incident details
        incident = db.query(Incident).filter_by(id=incident_id).first()
        if not incident:
            return {'status': 'error', 'error': f'Incident {incident_id} not found'}

        # Extract affected systems from incident description or evidence
        affected_systems = extract_affected_systems(incident)

        manager = NetworkIsolationManager()

        for system_ip in affected_systems:
            isolation_result = manager.isolate_system(
                target_ip=system_ip,
                incident_id=incident_id,
                reason=f"Automated isolation for incident: {incident.title}"
            )

            if isolation_result['status'] == 'success':
                results['systems_isolated'].append({
                    'ip': system_ip,
                    'details': isolation_result
                })
            else:
                results['systems_failed'].append({
                    'ip': system_ip,
                    'error': isolation_result.get('errors', ['Unknown error'])
                })
                results['overall_status'] = 'partial'

        logging.info(f"Isolation completed for incident {incident_id}: {len(results['systems_isolated'])} isolated, {len(results['systems_failed'])} failed")

    except Exception as e:
        results['overall_status'] = 'error'
        results['error'] = str(e)
        logging.error(f"Automated isolation failed for incident {incident_id}: {e}")
    finally:
        close_session(db)

    return results

def extract_affected_systems(incident: Incident) -> List[str]:
    """
    Extract affected system IPs from incident data

    Args:
        incident: Incident object

    Returns:
        List of IP addresses affected by the incident
    """
    affected_ips = []

    # Extract from description
    import re
    ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    description_ips = re.findall(ip_pattern, incident.description or '')
    affected_ips.extend(description_ips)

    # Extract from evidence (if available)
    # This would be enhanced based on actual evidence structure

    # Remove duplicates and validate IPs
    unique_ips = []
    for ip in affected_ips:
        if ip not in unique_ips and is_valid_ip(ip):
            unique_ips.append(ip)

    return unique_ips

def is_valid_ip(ip: str) -> bool:
    """Basic IP address validation"""
    import ipaddress
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

if __name__ == "__main__":
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Example usage
    if len(sys.argv) < 2:
        print("Usage: python network_isolation_integration.py <command> [args...]")
        print("Commands:")
        print("  isolate <ip> <incident_id> [reason]    - Isolate a system")
        print("  restore <ip> <incident_id> [reason]    - Restore a system")
        print("  status [ip]                           - Check isolation status")
        print("  setup-vbox [vm_name]                  - Setup VirtualBox networking")
        print("  isolate-incident <incident_id>        - Auto-isolate incident systems")
        sys.exit(1)

    manager = NetworkIsolationManager()
    command = sys.argv[1]

    try:
        if command == 'isolate' and len(sys.argv) >= 4:
            target_ip = sys.argv[2]
            incident_id = sys.argv[3]
            reason = sys.argv[4] if len(sys.argv) > 4 else "Manual isolation"
            result = manager.isolate_system(target_ip, incident_id, reason)
            print(json.dumps(result, indent=2, default=str))

        elif command == 'restore' and len(sys.argv) >= 4:
            target_ip = sys.argv[2]
            incident_id = sys.argv[3]
            reason = sys.argv[4] if len(sys.argv) > 4 else "Manual restoration"
            result = manager.restore_system(target_ip, incident_id, reason)
            print(json.dumps(result, indent=2, default=str))

        elif command == 'status':
            target_ip = sys.argv[2] if len(sys.argv) > 2 else None
            result = manager.get_isolation_status(target_ip)
            print(json.dumps(result, indent=2, default=str))

        elif command == 'setup-vbox':
            vm_name = sys.argv[2] if len(sys.argv) > 2 else None
            result = manager.setup_virtualbox_networking(vm_name)
            print(json.dumps(result, indent=2, default=str))

        elif command == 'isolate-incident' and len(sys.argv) >= 3:
            incident_id = sys.argv[2]
            result = isolate_incident_systems(incident_id)
            print(json.dumps(result, indent=2, default=str))

        else:
            print(f"Invalid command or insufficient arguments: {command}")
            sys.exit(1)

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)