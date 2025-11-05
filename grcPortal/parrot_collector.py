"""
Parrot OS Live Data Collection Module

This module provides live data collection capabilities from Parrot OS systems
for digital evidence management and security monitoring. It collects:

- System state information (uptime, load, memory, disk usage)
- Running process information with security context
- Network connection data with process correlation
- File system evidence collection
- Memory analysis using Volatility
- Disk acquisition using forensic imaging tools

The module uses SSH connections to securely collect data from remote Parrot OS systems
and stores the information in the GRC Portal database for analysis and reporting.
"""

import paramiko
import json
import logging
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from contextlib import contextmanager
import socket
import psutil
import os

from db import get_session, close_session
# from models import LiveSystemState, LiveProcessInfo, LiveNetworkConnection, MemoryAnalysis, DiskImage

@dataclass
class ParrotConnectionConfig:
    """Configuration for Parrot OS system connection"""
    hostname: str
    port: int = 22
    username: str = 'parrot'
    password: Optional[str] = None
    key_filename: Optional[str] = None
    timeout: int = 30
    system_name: str = 'parrot-os'

@dataclass
class SystemState:
    """System state information from Parrot OS"""
    hostname: str
    uptime: str
    load_average: Tuple[float, float, float]
    memory_total: int
    memory_used: int
    memory_free: int
    memory_percent: float
    disk_total: int
    disk_used: int
    disk_free: int
    disk_percent: float
    cpu_count: int
    cpu_percent: float
    timestamp: datetime

@dataclass
class ProcessInfo:
    """Process information with security context"""
    pid: int
    name: str
    cmdline: str
    username: str
    cpu_percent: float
    memory_percent: float
    status: str
    create_time: float
    connections: List[Dict]
    security_context: Dict
    timestamp: datetime

@dataclass
class NetworkConnection:
    """Network connection information"""
    local_address: str
    remote_address: str
    status: str
    pid: Optional[int]
    process_name: Optional[str]
    protocol: str
    timestamp: datetime

@dataclass
class MemoryAnalysisResult:
    """Memory analysis result from Volatility"""
    system_name: str
    analysis_type: str
    profile: str
    total_processes: int
    suspicious_processes: int
    network_connections: int
    registry_hives: int
    analysis_output: Dict
    timestamp: datetime

@dataclass
class DiskImageResult:
    """Disk imaging result"""
    system_name: str
    source_device: str
    image_path: str
    image_size: int
    hash_value: str
    imaging_tool: str
    timestamp: datetime

class ParrotDataCollector:
    """Main collector class for Parrot OS live data"""

    def __init__(self, config: ParrotConnectionConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)

    @contextmanager
    def _get_ssh_connection(self):
        """Context manager for SSH connections"""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            # Connect using password or key
            if self.config.password:
                client.connect(
                    hostname=self.config.hostname,
                    port=self.config.port,
                    username=self.config.username,
                    password=self.config.password,
                    timeout=self.config.timeout
                )
            elif self.config.key_filename:
                key = paramiko.RSAKey.from_private_key_file(self.config.key_filename)
                client.connect(
                    hostname=self.config.hostname,
                    port=self.config.port,
                    username=self.config.username,
                    pkey=key,
                    timeout=self.config.timeout
                )
            else:
                raise ValueError("Either password or key_filename must be provided")

            yield client

        except Exception as e:
            self.logger.error(f"SSH connection failed to {self.config.hostname}: {e}")
            raise
        finally:
            client.close()

    def _execute_command(self, client: paramiko.SSHClient, command: str) -> Tuple[str, str]:
        """Execute command on remote system and return stdout, stderr"""
        stdin, stdout, stderr = client.exec_command(command)
        return stdout.read().decode('utf-8').strip(), stderr.read().decode('utf-8').strip()

    def collect_system_state(self) -> Optional[SystemState]:
        """Collect comprehensive system state information"""
        try:
            with self._get_ssh_connection() as client:
                # Get hostname
                hostname, _ = self._execute_command(client, "hostname")

                # Get uptime
                uptime, _ = self._execute_command(client, "uptime -p")

                # Get load average
                load_output, _ = self._execute_command(client, "uptime")
                # Parse load average from uptime output
                load_parts = load_output.split("load average:")
                if len(load_parts) > 1:
                    load_values = load_parts[1].strip().split(", ")
                    load_avg = tuple(float(x.strip()) for x in load_values)
                else:
                    load_avg = (0.0, 0.0, 0.0)

                # Get memory information
                mem_output, _ = self._execute_command(client, "free -b")
                mem_lines = mem_output.split('\n')
                if len(mem_lines) >= 2:
                    mem_parts = mem_lines[1].split()
                    memory_total = int(mem_parts[0])
                    memory_used = int(mem_parts[1])
                    memory_free = int(mem_parts[2])
                    memory_percent = (memory_used / memory_total) * 100 if memory_total > 0 else 0
                else:
                    memory_total = memory_used = memory_free = memory_percent = 0

                # Get disk usage (root filesystem)
                disk_output, _ = self._execute_command(client, "df -B1 / | tail -1")
                disk_parts = disk_output.split()
                if len(disk_parts) >= 5:
                    disk_total = int(disk_parts[1])
                    disk_used = int(disk_parts[2])
                    disk_free = int(disk_parts[3])
                    disk_percent = float(disk_parts[4].rstrip('%'))
                else:
                    disk_total = disk_used = disk_free = disk_percent = 0

                # Get CPU information
                cpu_count, _ = self._execute_command(client, "nproc")
                cpu_count = int(cpu_count) if cpu_count.isdigit() else 1

                # Get CPU usage (simplified - would need more complex parsing for accurate %)
                cpu_output, _ = self._execute_command(client, "top -bn1 | grep 'Cpu(s)'")
                cpu_percent = 0.0
                if cpu_output:
                    # Parse CPU usage from top output
                    import re
                    cpu_match = re.search(r'(\d+\.\d+)%us', cpu_output)
                    if cpu_match:
                        cpu_percent = float(cpu_match.group(1))

                timestamp = datetime.now(timezone.utc)

                return SystemState(
                    hostname=hostname,
                    uptime=uptime,
                    load_average=load_avg,
                    memory_total=memory_total,
                    memory_used=memory_used,
                    memory_free=memory_free,
                    memory_percent=memory_percent,
                    disk_total=disk_total,
                    disk_used=disk_used,
                    disk_free=disk_free,
                    disk_percent=disk_percent,
                    cpu_count=cpu_count,
                    cpu_percent=cpu_percent,
                    timestamp=timestamp
                )

        except Exception as e:
            self.logger.error(f"Failed to collect system state: {e}")
            return None

    def collect_process_info(self) -> List[ProcessInfo]:
        """Collect running process information with security context"""
        processes = []
        try:
            with self._get_ssh_connection() as client:
                # Get process information using ps with security context
                ps_command = "ps aux --no-headers"
                ps_output, _ = self._execute_command(client, ps_command)

                timestamp = datetime.now(timezone.utc)

                for line in ps_output.split('\n'):
                    if not line.strip():
                        continue

                    parts = line.split(None, 10)  # Split on whitespace, max 11 parts
                    if len(parts) < 11:
                        continue

                    try:
                        username = parts[0]
                        pid = int(parts[1])
                        cpu_percent = float(parts[2])
                        memory_percent = float(parts[3])
                        # Skip VSZ, RSS
                        status = parts[7]
                        create_time_str = parts[8]  # This is actually start time, not create time
                        cmdline = parts[10] if len(parts) > 10 else ""

                        # Get process name from cmdline
                        name = cmdline.split()[0] if cmdline else "unknown"

                        # Get security context if available
                        security_context = {}
                        try:
                            # Try to get SELinux context if available
                            se_context, _ = self._execute_command(client, f"ps -p {pid} -Z | grep -v LABEL")
                            if se_context and ':' in se_context:
                                security_context['selinux'] = se_context.strip()
                        except:
                            pass

                        # Get network connections for this process
                        connections = []
                        try:
                            net_cmd = f"netstat -tlnp 2>/dev/null | grep ':{pid}/' || ss -tlnp | grep 'pid={pid},'"
                            net_output, _ = self._execute_command(client, net_cmd)
                            for net_line in net_output.split('\n'):
                                if net_line.strip():
                                    connections.append({'details': net_line.strip()})
                        except:
                            pass

                        process = ProcessInfo(
                            pid=pid,
                            name=name,
                            cmdline=cmdline,
                            username=username,
                            cpu_percent=cpu_percent,
                            memory_percent=memory_percent,
                            status=status,
                            create_time=time.time(),  # Approximate
                            connections=connections,
                            security_context=security_context,
                            timestamp=timestamp
                        )
                        processes.append(process)

                    except (ValueError, IndexError) as e:
                        self.logger.warning(f"Failed to parse process line: {line} - {e}")
                        continue

        except Exception as e:
            self.logger.error(f"Failed to collect process information: {e}")

        return processes

    def collect_network_connections(self) -> List[NetworkConnection]:
        """Collect network connection information"""
        connections = []
        try:
            with self._get_ssh_connection() as client:
                # Get network connections using ss (more modern than netstat)
                net_cmd = "ss -tuln -p 2>/dev/null || netstat -tuln -p 2>/dev/null"
                net_output, _ = self._execute_command(client, net_cmd)

                timestamp = datetime.now(timezone.utc)

                for line in net_output.split('\n'):
                    if not line.strip() or line.startswith('State') or line.startswith('Proto'):
                        continue

                    parts = line.split()
                    if len(parts) < 5:
                        continue

                    try:
                        protocol = parts[0]
                        local_addr = parts[4] if len(parts) > 4 else ""
                        remote_addr = parts[5] if len(parts) > 5 else ""
                        status = parts[1] if len(parts) > 1 else "UNKNOWN"

                        # Extract PID if available
                        pid = None
                        process_name = None
                        if len(parts) > 6:
                            pid_info = parts[6]
                            if 'pid=' in pid_info:
                                pid_part = pid_info.split('pid=')[1].split(',')[0]
                                try:
                                    pid = int(pid_part)
                                    # Get process name
                                    proc_cmd, _ = self._execute_command(client, f"ps -p {pid} -o comm= 2>/dev/null || echo 'unknown'")
                                    process_name = proc_cmd.strip() or "unknown"
                                except:
                                    pass

                        connection = NetworkConnection(
                            local_address=local_addr,
                            remote_address=remote_addr,
                            status=status,
                            pid=pid,
                            process_name=process_name,
                            protocol=protocol,
                            timestamp=timestamp
                        )
                        connections.append(connection)

                    except (ValueError, IndexError) as e:
                        self.logger.warning(f"Failed to parse network line: {line} - {e}")
                        continue

        except Exception as e:
            self.logger.error(f"Failed to collect network connections: {e}")

        return connections

    def collect_file_system_evidence(self, paths: List[str]) -> Dict[str, Dict]:
        """Collect file system evidence from specified paths"""
        evidence = {}
        try:
            with self._get_ssh_connection() as client:
                for path in paths:
                    try:
                        # Get file metadata
                        stat_cmd = f"stat -c '%a,%U,%G,%s,%Y,%n' '{path}' 2>/dev/null"
                        stat_output, _ = self._execute_command(client, stat_cmd)

                        if stat_output:
                            parts = stat_output.split(',', 5)
                            if len(parts) >= 6:
                                permissions, owner, group, size, mtime, filepath = parts
                                evidence[path] = {
                                    'permissions': permissions,
                                    'owner': owner,
                                    'group': group,
                                    'size': int(size),
                                    'mtime': datetime.fromtimestamp(int(mtime), timezone.utc),
                                    'path': filepath,
                                    'exists': True,
                                    'collected_at': datetime.now(timezone.utc)
                                }
                            else:
                                evidence[path] = {
                                    'exists': False,
                                    'error': 'Failed to parse stat output',
                                    'collected_at': datetime.now(timezone.utc)
                                }
                        else:
                            evidence[path] = {
                                'exists': False,
                                'error': 'File not found or access denied',
                                'collected_at': datetime.now(timezone.utc)
                            }

                    except Exception as e:
                        evidence[path] = {
                            'exists': False,
                            'error': str(e),
                            'collected_at': datetime.now(timezone.utc)
                        }

        except Exception as e:
            self.logger.error(f"Failed to collect file system evidence: {e}")

        return evidence

    def perform_memory_analysis(self, memory_image_path: str = None) -> Optional[MemoryAnalysisResult]:
        """Perform memory analysis using Volatility"""
        try:
            with self._get_ssh_connection() as client:
                timestamp = datetime.now(timezone.utc)

                # Check if Volatility is installed
                vol_check, _ = self._execute_command(client, "which vol || which volatility")
                if not vol_check.strip():
                    self.logger.warning("Volatility not found on remote system")
                    return None

                # If no memory image provided, try to create one
                if not memory_image_path:
                    # Try to create a memory dump
                    memory_image_path = f"/tmp/memory_dump_{int(time.time())}.lime"

                    # Try LiME first
                    lime_cmd = f"sudo insmod /usr/lib/modules/$(uname -r)/kernel/drivers/misc/lime.ko \"path={memory_image_path} format=lime\" 2>/dev/null || echo 'LiME failed'"
                    self._execute_command(client, lime_cmd)

                    # Check if dump was created
                    check_cmd = f"ls -la {memory_image_path}"
                    check_output, _ = self._execute_command(client, check_cmd)
                    if not check_output.strip():
                        self.logger.warning("Failed to create memory dump")
                        return None

                # Detect profile
                profile = "Linux"  # Default for Parrot OS
                try:
                    # Try to detect profile with Volatility 3
                    info_cmd = f"vol -f {memory_image_path} linux.info 2>/dev/null | head -10"
                    info_output, _ = self._execute_command(client, info_cmd)
                    if "Linux" in info_output:
                        profile = "Linux"
                except:
                    pass

                # Perform analysis
                analysis_output = {}

                # Get process list
                ps_cmd = f"vol -f {memory_image_path} linux.pslist 2>/dev/null || volatility -f {memory_image_path} --profile={profile} pslist 2>/dev/null"
                ps_output, _ = self._execute_command(client, ps_cmd)
                total_processes = len([line for line in ps_output.split('\n') if line.strip() and not line.startswith('PID')])

                # Get suspicious processes
                suspicious_processes = 0
                for line in ps_output.split('\n'):
                    if any(keyword in line.lower() for keyword in ['cmd', 'powershell', 'suspicious', 'unknown', 'meterpreter', 'shell']):
                        suspicious_processes += 1

                # Get network connections
                net_cmd = f"vol -f {memory_image_path} linux.netstat 2>/dev/null || volatility -f {memory_image_path} --profile={profile} netscan 2>/dev/null"
                net_output, _ = self._execute_command(client, net_cmd)
                network_connections = len([line for line in net_output.split('\n') if line.strip() and not line.startswith('Proto')])

                # Store analysis results
                analysis_output['process_list'] = ps_output[:1000]  # First 1000 chars
                analysis_output['network_connections'] = net_output[:1000]
                analysis_output['profile'] = profile

                return MemoryAnalysisResult(
                    system_name=self.config.system_name,
                    analysis_type="volatility_basic",
                    profile=profile,
                    total_processes=total_processes,
                    suspicious_processes=suspicious_processes,
                    network_connections=network_connections,
                    registry_hives=0,  # Not applicable for Linux
                    analysis_output=analysis_output,
                    timestamp=timestamp
                )

        except Exception as e:
            self.logger.error(f"Failed to perform memory analysis: {e}")
            return None

    def perform_disk_imaging(self, source_device: str, case_number: str) -> Optional[DiskImageResult]:
        """Perform forensic disk imaging using dc3dd or dd"""
        try:
            with self._get_ssh_connection() as client:
                timestamp = datetime.now(timezone.utc)

                # Create evidence directory
                evidence_dir = f"/evidence/case_{case_number}/disk_images"
                mkdir_cmd = f"sudo mkdir -p {evidence_dir}"
                self._execute_command(client, mkdir_cmd)

                # Generate image filename
                image_filename = f"disk_image_{int(time.time())}.dd"
                image_path = f"{evidence_dir}/{image_filename}"

                # Check available tools and perform imaging
                imaging_tool = "dd"  # Default

                # Try dc3dd first (better for forensics)
                dc3dd_check, _ = self._execute_command(client, "which dc3dd")
                if dc3dd_check.strip():
                    imaging_tool = "dc3dd"
                    imaging_cmd = f"sudo dc3dd if={source_device} of={image_path} hash=sha256 log={evidence_dir}/imaging_log.txt"
                else:
                    # Fallback to dd
                    imaging_cmd = f"sudo dd if={source_device} of={image_path} bs=4M status=progress"

                # Execute imaging
                imaging_output, imaging_error = self._execute_command(client, imaging_cmd)

                if imaging_error and "Permission denied" in imaging_error:
                    self.logger.error("Permission denied during disk imaging")
                    return None

                # Get image size
                size_cmd = f"sudo ls -la {image_path}"
                size_output, _ = self._execute_command(client, size_cmd)
                image_size = 0
                if size_output:
                    parts = size_output.split()
                    if len(parts) >= 5:
                        image_size = int(parts[4])

                # Generate hash
                hash_cmd = f"sudo sha256sum {image_path}"
                hash_output, _ = self._execute_command(client, hash_cmd)
                hash_value = hash_output.split()[0] if hash_output else ""

                return DiskImageResult(
                    system_name=self.config.system_name,
                    source_device=source_device,
                    image_path=image_path,
                    image_size=image_size,
                    hash_value=hash_value,
                    imaging_tool=imaging_tool,
                    timestamp=timestamp
                )

        except Exception as e:
            self.logger.error(f"Failed to perform disk imaging: {e}")
            return None

def collect_live_parrot_data(system_configs: List[ParrotConnectionConfig]) -> Dict[str, Dict]:
    """
    Main function to collect live data from multiple Parrot OS systems

    Args:
        system_configs: List of ParrotConnectionConfig objects

    Returns:
        Dict containing collected data organized by system
    """
    results = {
        'timestamp': datetime.now(timezone.utc),
        'systems': {},
        'errors': []
    }

    for config in system_configs:
        system_results = {
            'system_name': config.system_name,
            'hostname': config.hostname,
            'status': 'success',
            'system_state': None,
            'processes': [],
            'network_connections': [],
            'file_evidence': {},
            'memory_analysis': None,
            'disk_imaging': None,
            'error': None
        }

        try:
            collector = ParrotDataCollector(config)

            # Collect system state
            system_state = collector.collect_system_state()
            system_results['system_state'] = system_state

            # Collect process information
            processes = collector.collect_process_info()
            system_results['processes'] = processes

            # Collect network connections
            network_connections = collector.collect_network_connections()
            system_results['network_connections'] = network_connections

            # Collect file system evidence (configurable paths)
            evidence_paths = [
                '/var/log/auth.log',
                '/var/log/syslog',
                '/etc/passwd',
                '/etc/shadow',
                '/proc/version'
            ]
            file_evidence = collector.collect_file_system_evidence(evidence_paths)
            system_results['file_evidence'] = file_evidence

            # Perform memory analysis
            memory_analysis = collector.perform_memory_analysis()
            system_results['memory_analysis'] = memory_analysis

        except Exception as e:
            system_results['status'] = 'error'
            system_results['error'] = str(e)
            results['errors'].append(f"Failed to collect data from {config.hostname}: {e}")

        results['systems'][config.system_name] = system_results

    return results

def store_live_parrot_data(collection_results: Dict) -> bool:
    """
    Store collected live data in the database

    Args:
        collection_results: Results from collect_live_parrot_data

    Returns:
        bool: True if successful, False otherwise
    """
    db = get_session()
    success = False

    try:
        for system_name, system_data in collection_results['systems'].items():
            if system_data['status'] != 'success':
                continue

            # Store system state
            if system_data['system_state']:
                state = system_data['system_state']
                db_system_state = LiveSystemState(
                    system_name=system_name,
                    hostname=state.hostname,
                    uptime=state.uptime,
                    load_average_1m=state.load_average[0],
                    load_average_5m=state.load_average[1],
                    load_average_15m=state.load_average[2],
                    memory_total=state.memory_total,
                    memory_used=state.memory_used,
                    memory_free=state.memory_free,
                    memory_percent=state.memory_percent,
                    disk_total=state.disk_total,
                    disk_used=state.disk_used,
                    disk_free=state.disk_free,
                    disk_percent=state.disk_percent,
                    cpu_count=state.cpu_count,
                    cpu_percent=state.cpu_percent,
                    collected_at=state.timestamp
                )
                db.add(db_system_state)

            # Store process information
            for process in system_data['processes']:
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

            # Store network connections
            for connection in system_data['network_connections']:
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

            # Store memory analysis results
            if system_data['memory_analysis']:
                analysis = system_data['memory_analysis']
                db_analysis = MemoryAnalysis(
                    system_name=analysis.system_name,
                    analysis_type=analysis.analysis_type,
                    profile=analysis.profile,
                    total_processes=analysis.total_processes,
                    suspicious_processes=analysis.suspicious_processes,
                    network_connections=analysis.network_connections,
                    registry_hives=analysis.registry_hives,
                    analysis_output=json.dumps(analysis.analysis_output),
                    analyzed_at=analysis.timestamp
                )
                db.add(db_analysis)

        db.commit()
        success = True

    except Exception as e:
        db.rollback()
        logging.error(f"Failed to store live Parrot data: {e}")
        success = False
    finally:
        close_session(db)

    return success

# Configuration for Parrot OS systems (would be loaded from config file in production)
DEFAULT_PARROT_CONFIGS = [
    ParrotConnectionConfig(
        hostname="192.168.1.100",  # Example IP - would be configured per environment
        username="parrot",
        password="parrot",  # In production, use key-based auth
        system_name="parrot-incident-response"
    )
]

def perform_live_parrot_collection() -> Dict[str, any]:
    """
    Scheduled function to perform live data collection from configured Parrot OS systems

    Returns:
        Dict with collection results and status
    """
    logging.info("Starting live Parrot OS data collection")

    try:
        # In production, load configs from database or config file
        configs = DEFAULT_PARROT_CONFIGS

        # Collect data
        collection_results = collect_live_parrot_data(configs)

        # Store in database
        storage_success = store_live_parrot_data(collection_results)

        results = {
            'status': 'success' if storage_success else 'partial_success',
            'collection_results': collection_results,
            'storage_success': storage_success,
            'timestamp': datetime.now(timezone.utc)
        }

        if storage_success:
            logging.info("Live Parrot OS data collection completed successfully")
        else:
            logging.warning("Live Parrot OS data collection completed but storage failed")

        return results

    except Exception as e:
        logging.error(f"Live Parrot OS data collection failed: {e}")
        return {
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now(timezone.utc)
        }

def perform_memory_analysis(system_config: ParrotConnectionConfig, memory_image_path: str = None) -> Dict[str, any]:
    """
    Perform memory analysis on a Parrot OS system

    Args:
        system_config: ParrotConnectionConfig for the target system
        memory_image_path: Path to memory image (optional, will create if not provided)

    Returns:
        Dict with analysis results
    """
    logging.info(f"Starting memory analysis for {system_config.system_name}")

    try:
        collector = ParrotDataCollector(system_config)
        analysis_result = collector.perform_memory_analysis(memory_image_path)

        if analysis_result:
            # Store in database
            db = get_session()
            try:
                db_analysis = MemoryAnalysis(
                    system_name=analysis_result.system_name,
                    analysis_type=analysis_result.analysis_type,
                    profile=analysis_result.profile,
                    total_processes=analysis_result.total_processes,
                    suspicious_processes=analysis_result.suspicious_processes,
                    network_connections=analysis_result.network_connections,
                    registry_hives=analysis_result.registry_hives,
                    analysis_output=json.dumps(analysis_result.analysis_output),
                    analyzed_at=analysis_result.timestamp
                )
                db.add(db_analysis)
                db.commit()

                return {
                    'status': 'success',
                    'analysis_result': analysis_result,
                    'timestamp': datetime.now(timezone.utc)
                }
            finally:
                close_session(db)
        else:
            return {
                'status': 'error',
                'error': 'Memory analysis failed or Volatility not available',
                'timestamp': datetime.now(timezone.utc)
            }

    except Exception as e:
        logging.error(f"Memory analysis failed: {e}")
        return {
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now(timezone.utc)
        }

def perform_disk_imaging(system_config: ParrotConnectionConfig, source_device: str, case_number: str) -> Dict[str, any]:
    """
    Perform forensic disk imaging on a Parrot OS system

    Args:
        system_config: ParrotConnectionConfig for the target system
        source_device: Device to image (e.g., /dev/sda)
        case_number: Case identifier for the imaging operation

    Returns:
        Dict with imaging results
    """
    logging.info(f"Starting disk imaging for {system_config.system_name}, case: {case_number}")

    try:
        collector = ParrotDataCollector(system_config)
        imaging_result = collector.perform_disk_imaging(source_device, case_number)

        if imaging_result:
            # Store in database
            db = get_session()
            try:
                db_image = DiskImage(
                    system_name=imaging_result.system_name,
                    source_device=imaging_result.source_device,
                    image_path=imaging_result.image_path,
                    image_size=imaging_result.image_size,
                    hash_value=imaging_result.hash_value,
                    imaging_tool=imaging_result.imaging_tool,
                    created_at=imaging_result.timestamp
                )
                db.add(db_image)
                db.commit()

                return {
                    'status': 'success',
                    'imaging_result': imaging_result,
                    'timestamp': datetime.now(timezone.utc)
                }
            finally:
                close_session(db)
        else:
            return {
                'status': 'error',
                'error': 'Disk imaging failed',
                'timestamp': datetime.now(timezone.utc)
            }

    except Exception as e:
        logging.error(f"Disk imaging failed: {e}")
        return {
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now(timezone.utc)
        }

if __name__ == "__main__":
    # Test the collection functionality
    logging.basicConfig(level=logging.INFO)
    result = perform_live_parrot_collection()
    print(json.dumps(result, indent=2, default=str))