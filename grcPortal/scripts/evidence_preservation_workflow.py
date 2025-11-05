#!/usr/bin/env python3
"""
Evidence Preservation Workflow for GRC Portal IR Environment

This script implements comprehensive evidence preservation workflows including:
- Live data collection from Parrot OS systems
- Memory analysis using Volatility
- Disk imaging with forensic integrity
- Chain of custody documentation
- Evidence correlation and timeline creation
"""

import os
import sys
import json
import logging
import hashlib
import subprocess
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db import get_session, close_session
from models import (
    Incident, Evidence, LiveSystemState, LiveProcessInfo,
    LiveNetworkConnection, LiveFileEvidence, MemoryAnalysis,
    DiskImage, SecurityTimeline, TimelineEvent
)
from parrot_collector import ParrotDataCollector, ParrotConnectionConfig

class EvidencePreservationManager:
    """Manages comprehensive evidence preservation workflows"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.scripts_dir = os.path.join(os.path.dirname(__file__))

    def collect_live_evidence(self, system_config: ParrotConnectionConfig,
                            incident_id: str, evidence_types: List[str] = None) -> Dict[str, any]:
        """
        Collect live evidence from a Parrot OS system for incident response

        Args:
            system_config: ParrotConnectionConfig for target system
            incident_id: Associated incident identifier
            evidence_types: List of evidence types to collect (system_state, processes, network, files, memory)

        Returns:
            Dict with collection results and evidence details
        """
        if evidence_types is None:
            evidence_types = ['system_state', 'processes', 'network', 'files']

        self.logger.info(f"Starting live evidence collection from {system_config.system_name} for incident {incident_id}")

        results = {
            'system_name': system_config.system_name,
            'incident_id': incident_id,
            'collection_time': datetime.now(timezone.utc),
            'evidence_types': evidence_types,
            'collected_evidence': {},
            'errors': [],
            'chain_of_custody': []
        }

        collector = ParrotDataCollector(system_config)

        try:
            # 1. Collect system state
            if 'system_state' in evidence_types:
                system_state = collector.collect_system_state()
                if system_state:
                    results['collected_evidence']['system_state'] = self._store_system_state(system_config.system_name, system_state)
                    results['chain_of_custody'].append({
                        'action': 'collected_system_state',
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                        'evidence_type': 'system_state',
                        'description': f'Collected system state from {system_config.system_name}'
                    })

            # 2. Collect process information
            if 'processes' in evidence_types:
                processes = collector.collect_process_info()
                if processes:
                    results['collected_evidence']['processes'] = self._store_process_info(system_config.system_name, processes)
                    results['chain_of_custody'].append({
                        'action': 'collected_processes',
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                        'evidence_type': 'process_list',
                        'description': f'Collected {len(processes)} running processes from {system_config.system_name}'
                    })

            # 3. Collect network connections
            if 'network' in evidence_types:
                connections = collector.collect_network_connections()
                if connections:
                    results['collected_evidence']['network'] = self._store_network_connections(system_config.system_name, connections)
                    results['chain_of_custody'].append({
                        'action': 'collected_network',
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                        'evidence_type': 'network_connections',
                        'description': f'Collected {len(connections)} network connections from {system_config.system_name}'
                    })

            # 4. Collect file system evidence
            if 'files' in evidence_types:
                file_paths = [
                    '/var/log/auth.log',
                    '/var/log/syslog',
                    '/etc/passwd',
                    '/etc/shadow',
                    '/proc/version',
                    '/var/log/wazuh/ossec.log'
                ]
                file_evidence = collector.collect_file_system_evidence(file_paths)
                if file_evidence:
                    results['collected_evidence']['files'] = self._store_file_evidence(system_config.system_name, file_evidence)
                    results['chain_of_custody'].append({
                        'action': 'collected_files',
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                        'evidence_type': 'file_evidence',
                        'description': f'Collected file system evidence from {len(file_evidence)} paths on {system_config.system_name}'
                    })

            # 5. Perform memory analysis
            if 'memory' in evidence_types:
                memory_analysis = collector.perform_memory_analysis()
                if memory_analysis:
                    results['collected_evidence']['memory'] = self._store_memory_analysis(memory_analysis)
                    results['chain_of_custody'].append({
                        'action': 'performed_memory_analysis',
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                        'evidence_type': 'memory_analysis',
                        'description': f'Performed memory analysis on {system_config.system_name} using Volatility'
                    })

            # Link evidence to incident
            self._link_evidence_to_incident(incident_id, results)

            self.logger.info(f"Live evidence collection completed for {system_config.system_name}")

        except Exception as e:
            error_msg = f"Evidence collection failed for {system_config.system_name}: {str(e)}"
            results['errors'].append(error_msg)
            self.logger.error(error_msg)

        return results

    def perform_forensic_disk_imaging(self, system_config: ParrotConnectionConfig,
                                    source_device: str, case_number: str,
                                    incident_id: str) -> Dict[str, any]:
        """
        Perform forensic disk imaging with integrity verification

        Args:
            system_config: ParrotConnectionConfig for target system
            source_device: Device to image (e.g., /dev/sda)
            case_number: Case identifier for the imaging operation
            incident_id: Associated incident identifier

        Returns:
            Dict with imaging results and integrity verification
        """
        self.logger.info(f"Starting forensic disk imaging for case {case_number}, incident {incident_id}")

        results = {
            'case_number': case_number,
            'incident_id': incident_id,
            'source_device': source_device,
            'system_name': system_config.system_name,
            'imaging_time': datetime.now(timezone.utc),
            'integrity_verified': False,
            'chain_of_custody': [],
            'errors': []
        }

        collector = ParrotDataCollector(system_config)

        try:
            # Perform disk imaging
            imaging_result = collector.perform_disk_imaging(source_device, case_number)

            if imaging_result:
                results['imaging_result'] = imaging_result
                results['chain_of_custody'].append({
                    'action': 'disk_imaging_performed',
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'evidence_type': 'disk_image',
                    'description': f'Created forensic disk image of {source_device} using {imaging_result.imaging_tool}',
                    'hash_value': imaging_result.hash_value,
                    'image_size': imaging_result.image_size
                })

                # Verify image integrity
                integrity_result = self._verify_image_integrity(imaging_result.image_path, imaging_result.hash_value)
                results['integrity_verified'] = integrity_result['verified']
                results['integrity_check'] = integrity_result

                if results['integrity_verified']:
                    results['chain_of_custody'].append({
                        'action': 'integrity_verified',
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                        'evidence_type': 'disk_image',
                        'description': f'Verified integrity of disk image with SHA256: {imaging_result.hash_value}'
                    })

                # Link to incident
                self._link_disk_image_to_incident(incident_id, imaging_result)

                self.logger.info(f"Forensic disk imaging completed for case {case_number}")
            else:
                results['errors'].append("Disk imaging failed")

        except Exception as e:
            error_msg = f"Disk imaging failed: {str(e)}"
            results['errors'].append(error_msg)
            self.logger.error(error_msg)

        return results

    def create_evidence_timeline(self, incident_id: str, system_name: str = None) -> Dict[str, any]:
        """
        Create a comprehensive evidence timeline for an incident

        Args:
            incident_id: Incident identifier
            system_name: Optional system name filter

        Returns:
            Dict with timeline creation results
        """
        self.logger.info(f"Creating evidence timeline for incident {incident_id}")

        results = {
            'incident_id': incident_id,
            'system_name': system_name,
            'timeline_created': datetime.now(timezone.utc),
            'events_added': 0,
            'timeline_id': None,
            'errors': []
        }

        db = get_session()
        try:
            # Get incident details
            incident = db.query(Incident).filter_by(id=incident_id).first()
            if not incident:
                results['errors'].append(f"Incident {incident_id} not found")
                return results

            # Create timeline
            timeline = SecurityTimeline(
                title=f"Evidence Timeline - Incident {incident.title}",
                description=f"Comprehensive evidence timeline for incident investigation",
                analysis_period_start=incident.reported_at,
                analysis_period_end=datetime.now(timezone.utc),
                incident_id=incident_id,
                source_systems=json.dumps(["Parrot OS", "macOS", "Windows"] if not system_name else [system_name]),
                status="analyzing"
            )

            db.add(timeline)
            db.flush()  # Get timeline ID

            results['timeline_id'] = timeline.id

            # Add evidence collection events
            evidence_events = self._collect_timeline_events(db, incident_id, system_name)
            for event_data in evidence_events:
                timeline.add_event(**event_data)
                results['events_added'] += 1

            # Generate attack sequence and visualization data
            timeline.generate_attack_sequence()
            timeline.get_timeline_visualization_data()
            timeline.status = "completed"
            timeline.completed_at = datetime.now(timezone.utc)

            db.commit()

            self.logger.info(f"Evidence timeline created with {results['events_added']} events")

        except Exception as e:
            db.rollback()
            error_msg = f"Timeline creation failed: {str(e)}"
            results['errors'].append(error_msg)
            self.logger.error(error_msg)
        finally:
            close_session(db)

        return results

    def _store_system_state(self, system_name: str, system_state) -> Dict[str, any]:
        """Store system state evidence in database"""
        db = get_session()
        try:
            db_state = LiveSystemState(
                system_name=system_name,
                hostname=system_state.hostname,
                uptime=system_state.uptime,
                load_average_1m=system_state.load_average[0],
                load_average_5m=system_state.load_average[1],
                load_average_15m=system_state.load_average[2],
                memory_total=system_state.memory_total,
                memory_used=system_state.memory_used,
                memory_free=system_state.memory_free,
                memory_percent=system_state.memory_percent,
                disk_total=system_state.disk_total,
                disk_used=system_state.disk_used,
                disk_free=system_state.disk_free,
                disk_percent=system_state.disk_percent,
                cpu_count=system_state.cpu_count,
                cpu_percent=system_state.cpu_percent,
                collected_at=system_state.timestamp
            )
            db.add(db_state)
            db.commit()
            return {'id': db_state.id, 'status': 'stored'}
        finally:
            close_session(db)

    def _store_process_info(self, system_name: str, processes: List) -> Dict[str, any]:
        """Store process information evidence"""
        db = get_session()
        stored_count = 0
        try:
            for process in processes:
                db_process = LiveProcessInfo(
                    system_name=system_name,
                    pid=process.pid,
                    name=process.name,
                    cmdline=process.cmdline,
                    username=process.username,
                    cpu_percent=process.cpu_percent,
                    memory_percent=process.memory_percent,
                    status=process.status,
                    create_time=process.create_time,
                    connections=json.dumps(process.connections),
                    security_context=json.dumps(process.security_context),
                    collected_at=process.timestamp
                )
                db.add(db_process)
                stored_count += 1
            db.commit()
            return {'count': stored_count, 'status': 'stored'}
        finally:
            close_session(db)

    def _store_network_connections(self, system_name: str, connections: List) -> Dict[str, any]:
        """Store network connection evidence"""
        db = get_session()
        stored_count = 0
        try:
            for connection in connections:
                db_connection = LiveNetworkConnection(
                    system_name=system_name,
                    local_address=connection.local_address,
                    remote_address=connection.remote_address,
                    status=connection.status,
                    pid=connection.pid,
                    process_name=connection.process_name,
                    protocol=connection.protocol,
                    collected_at=connection.timestamp
                )
                db.add(db_connection)
                stored_count += 1
            db.commit()
            return {'count': stored_count, 'status': 'stored'}
        finally:
            close_session(db)

    def _store_file_evidence(self, system_name: str, file_evidence: Dict) -> Dict[str, any]:
        """Store file system evidence"""
        db = get_session()
        stored_count = 0
        try:
            for file_path, file_data in file_evidence.items():
                db_file = LiveFileEvidence(
                    system_name=system_name,
                    file_path=file_path,
                    permissions=file_data.get('permissions'),
                    owner=file_data.get('owner'),
                    group=file_data.get('group'),
                    size=file_data.get('size'),
                    mtime=file_data.get('mtime'),
                    exists=file_data.get('exists', False),
                    error_message=file_data.get('error'),
                    collected_at=file_data.get('collected_at', datetime.now(timezone.utc))
                )
                db.add(db_file)
                stored_count += 1
            db.commit()
            return {'count': stored_count, 'status': 'stored'}
        finally:
            close_session(db)

    def _store_memory_analysis(self, memory_analysis) -> Dict[str, any]:
        """Store memory analysis results"""
        db = get_session()
        try:
            db_analysis = MemoryAnalysis(
                system_name=memory_analysis.system_name,
                analysis_type=memory_analysis.analysis_type,
                profile=memory_analysis.profile,
                total_processes=memory_analysis.total_processes,
                suspicious_processes=memory_analysis.suspicious_processes,
                network_connections=memory_analysis.network_connections,
                registry_hives=memory_analysis.registry_hives,
                analysis_output=json.dumps(memory_analysis.analysis_output),
                analyzed_at=memory_analysis.timestamp
            )
            db.add(db_analysis)
            db.commit()
            return {'id': db_analysis.id, 'status': 'stored'}
        finally:
            close_session(db)

    def _verify_image_integrity(self, image_path: str, expected_hash: str) -> Dict[str, any]:
        """Verify integrity of disk image"""
        try:
            # Calculate actual hash
            sha256 = hashlib.sha256()
            with open(image_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256.update(chunk)
            actual_hash = sha256.hexdigest()

            verified = actual_hash == expected_hash
            return {
                'verified': verified,
                'expected_hash': expected_hash,
                'actual_hash': actual_hash,
                'algorithm': 'SHA256'
            }
        except Exception as e:
            return {
                'verified': False,
                'error': str(e),
                'algorithm': 'SHA256'
            }

    def _link_evidence_to_incident(self, incident_id: str, collection_results: Dict):
        """Link collected evidence to incident"""
        db = get_session()
        try:
            # Create evidence records linking to incident
            for evidence_type, evidence_data in collection_results['collected_evidence'].items():
                evidence = Evidence(
                    type="log" if evidence_type in ['system_state', 'processes', 'network'] else "document",
                    file_path=None,  # Live evidence stored in database
                    description=f"Live {evidence_type} evidence collected from {collection_results['system_name']}",
                    collected_by=1,  # Default system user
                    collected_at=collection_results['collection_time'],
                    storage_method="Database storage with integrity verification",
                    hash_value=None,  # Would be calculated for file-based evidence
                    incident_id=int(incident_id),
                    chain_of_custody=json.dumps(collection_results['chain_of_custody'])
                )
                db.add(evidence)
            db.commit()
        finally:
            close_session(db)

    def _link_disk_image_to_incident(self, incident_id: str, imaging_result):
        """Link disk image to incident"""
        db = get_session()
        try:
            evidence = Evidence(
                type="document",
                file_path=imaging_result.image_path,
                description=f"Forensic disk image of {imaging_result.source_device} created with {imaging_result.imaging_tool}",
                collected_by=1,  # Default system user
                collected_at=imaging_result.timestamp,
                storage_method="Secure forensic storage with hash verification",
                hash_value=imaging_result.hash_value,
                incident_id=int(incident_id),
                chain_of_custody=json.dumps([{
                    'action': 'disk_image_created',
                    'timestamp': imaging_result.timestamp.isoformat(),
                    'tool': imaging_result.imaging_tool,
                    'hash': imaging_result.hash_value
                }])
            )
            db.add(evidence)
            db.commit()
        finally:
            close_session(db)

    def _collect_timeline_events(self, db, incident_id: str, system_name: str = None) -> List[Dict]:
        """Collect timeline events from various evidence sources"""
        events = []

        # System state events
        query = db.query(LiveSystemState).filter(LiveSystemState.system_name == system_name) if system_name else db.query(LiveSystemState)
        for state in query.order_by(LiveSystemState.collected_at.desc()).limit(50).all():
            events.append({
                'timestamp': state.collected_at,
                'event_type': 'system_state',
                'source_system': state.system_name,
                'source_component': 'live_collection',
                'title': f'System State: {state.hostname}',
                'description': f'CPU: {state.cpu_percent:.1f}%, Memory: {state.memory_percent:.1f}%, Load: {state.load_average_1m:.2f}',
                'severity': 'info',
                'category': 'system',
                'tags': ['system_state', 'performance']
            })

        # Process events (suspicious processes)
        query = db.query(LiveProcessInfo).filter(LiveProcessInfo.system_name == system_name) if system_name else db.query(LiveProcessInfo)
        for process in query.filter(LiveProcessInfo.cpu_percent > 50).order_by(LiveProcessInfo.collected_at.desc()).limit(20).all():
            events.append({
                'timestamp': process.collected_at,
                'event_type': 'process_activity',
                'source_system': process.system_name,
                'source_component': 'process_monitor',
                'title': f'High CPU Process: {process.name}',
                'description': f'Process {process.name} (PID {process.pid}) using {process.cpu_percent:.1f}% CPU',
                'severity': 'medium' if process.cpu_percent > 80 else 'low',
                'category': 'process',
                'tags': ['process', 'performance']
            })

        # Network connection events
        query = db.query(LiveNetworkConnection).filter(LiveNetworkConnection.system_name == system_name) if system_name else db.query(LiveNetworkConnection)
        for conn in query.order_by(LiveNetworkConnection.collected_at.desc()).limit(30).all():
            events.append({
                'timestamp': conn.collected_at,
                'event_type': 'network_connection',
                'source_system': conn.system_name,
                'source_component': 'network_monitor',
                'title': f'Network Connection: {conn.local_address} -> {conn.remote_address}',
                'description': f'{conn.protocol} connection from {conn.local_address} to {conn.remote_address}',
                'severity': 'info',
                'category': 'network',
                'tags': ['network', 'connection']
            })

        return events

def perform_comprehensive_evidence_collection(incident_id: str, system_configs: List[ParrotConnectionConfig]) -> Dict[str, any]:
    """
    Perform comprehensive evidence collection for an incident

    Args:
        incident_id: Incident identifier
        system_configs: List of system configurations to collect from

    Returns:
        Dict with comprehensive collection results
    """
    logging.info(f"Starting comprehensive evidence collection for incident {incident_id}")

    manager = EvidencePreservationManager()
    results = {
        'incident_id': incident_id,
        'collection_start': datetime.now(timezone.utc),
        'systems_collected': [],
        'total_evidence': 0,
        'timeline_created': False,
        'errors': []
    }

    for config in system_configs:
        try:
            # Collect live evidence
            evidence_types = ['system_state', 'processes', 'network', 'files', 'memory']
            collection_result = manager.collect_live_evidence(config, incident_id, evidence_types)

            if collection_result and not collection_result.get('errors'):
                results['systems_collected'].append({
                    'system_name': config.system_name,
                    'evidence_collected': len(collection_result['collected_evidence']),
                    'details': collection_result
                })
                results['total_evidence'] += len(collection_result['collected_evidence'])
            else:
                results['errors'].extend(collection_result.get('errors', []))

        except Exception as e:
            results['errors'].append(f"Evidence collection failed for {config.system_name}: {str(e)}")

    # Create evidence timeline
    try:
        timeline_result = manager.create_evidence_timeline(incident_id)
        if timeline_result and timeline_result.get('timeline_id'):
            results['timeline_created'] = True
            results['timeline_id'] = timeline_result['timeline_id']
            results['timeline_events'] = timeline_result['events_added']
    except Exception as e:
        results['errors'].append(f"Timeline creation failed: {str(e)}")

    results['collection_end'] = datetime.now(timezone.utc)
    logging.info(f"Comprehensive evidence collection completed for incident {incident_id}")
    return results

if __name__ == "__main__":
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Example usage
    if len(sys.argv) < 3:
        print("Usage: python evidence_preservation_workflow.py <command> [args...]")
        print("Commands:")
        print("  collect-live <incident_id> <system_name> <hostname> [evidence_types]")
        print("  disk-image <incident_id> <system_name> <hostname> <device> <case_number>")
        print("  create-timeline <incident_id> [system_name]")
        print("  comprehensive <incident_id> <system_configs_json>")
        sys.exit(1)

    manager = EvidencePreservationManager()
    command = sys.argv[1]

    try:
        if command == 'collect-live' and len(sys.argv) >= 5:
            incident_id = sys.argv[2]
            system_name = sys.argv[3]
            hostname = sys.argv[4]
            evidence_types = sys.argv[5].split(',') if len(sys.argv) > 5 else None

            config = ParrotConnectionConfig(
                hostname=hostname,
                system_name=system_name,
                username="parrot",
                password="parrot"  # In production, use key-based auth
            )

            result = manager.collect_live_evidence(config, incident_id, evidence_types)
            print(json.dumps(result, indent=2, default=str))

        elif command == 'disk-image' and len(sys.argv) >= 7:
            incident_id = sys.argv[2]
            system_name = sys.argv[3]
            hostname = sys.argv[4]
            device = sys.argv[5]
            case_number = sys.argv[6]

            config = ParrotConnectionConfig(
                hostname=hostname,
                system_name=system_name,
                username="parrot",
                password="parrot"
            )

            result = manager.perform_forensic_disk_imaging(config, device, case_number, incident_id)
            print(json.dumps(result, indent=2, default=str))

        elif command == 'create-timeline' and len(sys.argv) >= 3:
            incident_id = sys.argv[2]
            system_name = sys.argv[3] if len(sys.argv) > 3 else None

            result = manager.create_evidence_timeline(incident_id, system_name)
            print(json.dumps(result, indent=2, default=str))

        elif command == 'comprehensive' and len(sys.argv) >= 4:
            incident_id = sys.argv[2]
            configs_json = sys.argv[3]

            # Parse system configs from JSON
            configs_data = json.loads(configs_json)
            system_configs = []
            for config_data in configs_data:
                config = ParrotConnectionConfig(**config_data)
                system_configs.append(config)

            result = perform_comprehensive_evidence_collection(incident_id, system_configs)
            print(json.dumps(result, indent=2, default=str))

        else:
            print(f"Invalid command or insufficient arguments: {command}")
            sys.exit(1)

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)