"""
Performance Metrics and Validation Evidence for GRC Portal

This module implements comprehensive performance monitoring, metrics collection,
and validation evidence tracking for the enterprise vulnerability management system.

Key Features:
- Real-time performance monitoring
- Automated metrics collection
- Validation evidence management
- Performance dashboards and reporting
- SLA tracking and compliance
- System health monitoring

Metrics Categories:
- Vulnerability Management Performance
- Assessment Tool Performance
- System Response Times
- User Activity Metrics
- Compliance Validation Metrics
- Security Control Effectiveness

Author: GRC Portal Development Team
"""

import json
import time
import psutil
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import threading
import statistics


class MetricType(Enum):
    """Types of performance metrics"""
    VULNERABILITY_MANAGEMENT = "vulnerability_management"
    ASSESSMENT_PERFORMANCE = "assessment_performance"
    SYSTEM_RESPONSE_TIME = "system_response_time"
    USER_ACTIVITY = "user_activity"
    COMPLIANCE_VALIDATION = "compliance_validation"
    SECURITY_CONTROL_EFFECTIVENESS = "security_control_effectiveness"
    SYSTEM_HEALTH = "system_health"


class ValidationEvidenceType(Enum):
    """Types of validation evidence"""
    AUTOMATED_TEST_RESULTS = "automated_test_results"
    MANUAL_REVIEW_DOCUMENTS = "manual_review_documents"
    AUDIT_LOGS = "audit_logs"
    COMPLIANCE_CERTIFICATES = "compliance_certificates"
    SECURITY_SCAN_RESULTS = "security_scan_results"
    CONTROL_IMPLEMENTATION_PROOF = "control_implementation_proof"


@dataclass
class PerformanceMetric:
    """Represents a performance metric measurement"""
    metric_id: str
    metric_type: MetricType
    name: str
    value: float
    unit: str
    timestamp: datetime
    tags: Dict[str, str] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.tags is None:
            self.tags = {}
        if self.metadata is None:
            self.metadata = {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert metric to dictionary for JSON serialization"""
        data = asdict(self)
        data['metric_type'] = self.metric_type.value
        data['timestamp'] = self.timestamp.isoformat()
        return data


@dataclass
class ValidationEvidence:
    """Represents validation evidence for assessments"""
    evidence_id: str
    evidence_type: ValidationEvidenceType
    title: str
    description: str
    source_system: str
    collected_at: datetime
    validated_at: Optional[datetime] = None
    validation_status: str = "pending"  # pending, validated, rejected
    evidence_data: Dict[str, Any] = None
    validation_criteria: Dict[str, Any] = None
    validator: Optional[str] = None
    confidence_score: float = 0.0

    def __post_init__(self):
        if self.evidence_data is None:
            self.evidence_data = {}
        if self.validation_criteria is None:
            self.validation_criteria = {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert evidence to dictionary for JSON serialization"""
        data = asdict(self)
        data['evidence_type'] = self.evidence_type.value
        data['collected_at'] = self.collected_at.isoformat()
        if self.validated_at:
            data['validated_at'] = self.validated_at.isoformat()
        return data

    def validate_evidence(self, validator: str, criteria: Dict[str, Any] = None) -> bool:
        """Validate the evidence against criteria"""
        self.validated_at = datetime.now(timezone.utc)
        self.validator = validator

        if criteria:
            self.validation_criteria.update(criteria)

        # Simple validation logic (in production, this would be more sophisticated)
        if self.evidence_type == ValidationEvidenceType.AUTOMATED_TEST_RESULTS:
            # Check if test results show passing status
            test_results = self.evidence_data.get('results', [])
            passed_tests = sum(1 for test in test_results if test.get('status') == 'passed')
            total_tests = len(test_results)
            if total_tests > 0:
                self.confidence_score = (passed_tests / total_tests) * 100
                self.validation_status = "validated" if self.confidence_score >= 80 else "rejected"
            else:
                self.validation_status = "rejected"
                self.confidence_score = 0.0

        elif self.evidence_type == ValidationEvidenceType.SECURITY_SCAN_RESULTS:
            # Check vulnerability findings
            findings = self.evidence_data.get('findings', [])
            critical_findings = sum(1 for finding in findings if finding.get('severity') == 'critical')
            if critical_findings == 0:
                self.validation_status = "validated"
                self.confidence_score = 95.0
            else:
                self.validation_status = "rejected"
                self.confidence_score = max(0, 100 - (critical_findings * 20))

        else:
            # Default validation
            self.validation_status = "validated"
            self.confidence_score = 85.0

        return self.validation_status == "validated"


@dataclass
class SLAMetric:
    """Service Level Agreement metrics tracking"""
    sla_id: str
    service_name: str
    metric_name: str
    target_value: float
    actual_value: float
    measurement_period: str  # daily, weekly, monthly
    compliance_status: str = "unknown"  # compliant, non_compliant, warning
    last_updated: datetime = None

    def __post_init__(self):
        if self.last_updated is None:
            self.last_updated = datetime.now(timezone.utc)

    def check_compliance(self) -> str:
        """Check SLA compliance status"""
        if self.metric_name in ["response_time", "downtime"]:
            # Lower is better
            if self.actual_value <= self.target_value:
                self.compliance_status = "compliant"
            elif self.actual_value <= self.target_value * 1.1:
                self.compliance_status = "warning"
            else:
                self.compliance_status = "non_compliant"
        else:
            # Higher is better
            if self.actual_value >= self.target_value:
                self.compliance_status = "compliant"
            elif self.actual_value >= self.target_value * 0.9:
                self.compliance_status = "warning"
            else:
                self.compliance_status = "non_compliant"

        return self.compliance_status


class PerformanceMonitor:
    """
    Real-time performance monitoring system

    Collects and analyzes system performance metrics including:
    - Response times and throughput
    - Resource utilization
    - Error rates and availability
    - User activity patterns
    """

    def __init__(self):
        self.metrics: List[PerformanceMetric] = []
        self.evidence_records: List[ValidationEvidence] = []
        self.sla_metrics: List[SLAMetric] = []
        self.monitoring_active = False
        self.monitoring_thread = None

    def start_monitoring(self):
        """Start the performance monitoring system"""
        if not self.monitoring_active:
            self.monitoring_active = True
            self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
            self.monitoring_thread.start()

    def stop_monitoring(self):
        """Stop the performance monitoring system"""
        self.monitoring_active = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)

    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                self._collect_system_metrics()
                self._collect_application_metrics()
                time.sleep(60)  # Collect metrics every minute
            except Exception as e:
                print(f"Error in monitoring loop: {e}")
                time.sleep(30)

    def _collect_system_metrics(self):
        """Collect system-level performance metrics"""
        timestamp = datetime.now(timezone.utc)

        # CPU usage
        self.record_metric(PerformanceMetric(
            metric_id=f"cpu_usage_{int(timestamp.timestamp())}",
            metric_type=MetricType.SYSTEM_HEALTH,
            name="CPU Usage",
            value=psutil.cpu_percent(interval=1),
            unit="percent",
            timestamp=timestamp,
            tags={"component": "system", "resource": "cpu"}
        ))

        # Memory usage
        memory = psutil.virtual_memory()
        self.record_metric(PerformanceMetric(
            metric_id=f"memory_usage_{int(timestamp.timestamp())}",
            metric_type=MetricType.SYSTEM_HEALTH,
            name="Memory Usage",
            value=memory.percent,
            unit="percent",
            timestamp=timestamp,
            tags={"component": "system", "resource": "memory"}
        ))

        # Disk usage
        disk = psutil.disk_usage('/')
        self.record_metric(PerformanceMetric(
            metric_id=f"disk_usage_{int(timestamp.timestamp())}",
            metric_type=MetricType.SYSTEM_HEALTH,
            name="Disk Usage",
            value=disk.percent,
            unit="percent",
            timestamp=timestamp,
            tags={"component": "system", "resource": "disk"}
        ))

    def _collect_application_metrics(self):
        """Collect application-specific performance metrics"""
        # This would integrate with Flask application metrics
        # For now, we'll collect basic application health metrics
        pass

    def record_metric(self, metric: PerformanceMetric):
        """Record a performance metric"""
        self.metrics.append(metric)

        # Keep only last 1000 metrics to prevent memory issues
        if len(self.metrics) > 1000:
            self.metrics = self.metrics[-1000:]

    def record_evidence(self, evidence: ValidationEvidence):
        """Record validation evidence"""
        self.evidence_records.append(evidence)

        # Keep only last 500 evidence records
        if len(self.evidence_records) > 500:
            self.evidence_records = self.evidence_records[-500:]

    def get_metrics_summary(self, metric_type: MetricType = None,
                          time_range_hours: int = 24) -> Dict[str, Any]:
        """Get summary statistics for metrics"""
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=time_range_hours)

        # Filter metrics
        filtered_metrics = [
            m for m in self.metrics
            if m.timestamp >= cutoff_time and
            (metric_type is None or m.metric_type == metric_type)
        ]

        if not filtered_metrics:
            return {
                'count': 0,
                'average': 0.0,
                'minimum': 0.0,
                'maximum': 0.0,
                'latest': None
            }

        values = [m.value for m in filtered_metrics]
        latest_metric = max(filtered_metrics, key=lambda m: m.timestamp)

        return {
            'count': len(filtered_metrics),
            'average': statistics.mean(values),
            'minimum': min(values),
            'maximum': max(values),
            'latest': latest_metric.to_dict() if latest_metric else None
        }

    def get_sla_status(self) -> Dict[str, Any]:
        """Get SLA compliance status"""
        compliant = sum(1 for sla in self.sla_metrics if sla.compliance_status == "compliant")
        warning = sum(1 for sla in self.sla_metrics if sla.compliance_status == "warning")
        non_compliant = sum(1 for sla in self.sla_metrics if sla.compliance_status == "non_compliant")

        return {
            'total_slas': len(self.sla_metrics),
            'compliant': compliant,
            'warning': warning,
            'non_compliant': non_compliant,
            'compliance_rate': (compliant / len(self.sla_metrics) * 100) if self.sla_metrics else 0
        }

    def generate_performance_report(self) -> str:
        """Generate comprehensive performance report"""
        report = f"""
PERFORMANCE METRICS AND VALIDATION REPORT
==========================================

Report Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}

SYSTEM HEALTH METRICS
=====================

CPU Usage (Last 24h):
{self._format_metric_summary(MetricType.SYSTEM_HEALTH, 'CPU Usage')}

Memory Usage (Last 24h):
{self._format_metric_summary(MetricType.SYSTEM_HEALTH, 'Memory Usage')}

Disk Usage (Last 24h):
{self._format_metric_summary(MetricType.SYSTEM_HEALTH, 'Disk Usage')}

VULNERABILITY MANAGEMENT PERFORMANCE
===================================

Assessment Performance (Last 24h):
{self._format_metric_summary(MetricType.ASSESSMENT_PERFORMANCE)}

Response Times (Last 24h):
{self._format_metric_summary(MetricType.SYSTEM_RESPONSE_TIME)}

VALIDATION EVIDENCE SUMMARY
===========================

Total Evidence Records: {len(self.evidence_records)}
Validated Evidence: {sum(1 for e in self.evidence_records if e.validation_status == 'validated')}
Pending Validation: {sum(1 for e in self.evidence_records if e.validation_status == 'pending')}
Rejected Evidence: {sum(1 for e in self.evidence_records if e.validation_status == 'rejected')}

Recent Evidence:
{self._format_recent_evidence()}

SLA COMPLIANCE STATUS
=====================

{self._format_sla_status()}

RECOMMENDATIONS
===============

{self._generate_recommendations()}
"""

        return report

    def _format_metric_summary(self, metric_type: MetricType, name_filter: str = None) -> str:
        """Format metric summary for reporting"""
        summary = self.get_metrics_summary(metric_type)

        if summary['count'] == 0:
            return "No data available"

        lines = [
            f"  Count: {summary['count']}",
            f"  Average: {summary['average']:.2f}",
            f"  Minimum: {summary['minimum']:.2f}",
            f"  Maximum: {summary['maximum']:.2f}"
        ]

        if summary['latest']:
            latest = summary['latest']
            lines.append(f"  Latest: {latest['value']:.2f} {latest['unit']} ({latest['timestamp']})")

        return "\n".join(lines)

    def _format_recent_evidence(self) -> str:
        """Format recent evidence for reporting"""
        if not self.evidence_records:
            return "No evidence records available"

        recent_evidence = sorted(self.evidence_records, key=lambda e: e.collected_at, reverse=True)[:5]

        lines = []
        for evidence in recent_evidence:
            status_icon = "✓" if evidence.validation_status == "validated" else "✗" if evidence.validation_status == "rejected" else "⏳"
            lines.append(f"  {status_icon} {evidence.title} ({evidence.evidence_type.value}) - {evidence.validation_status}")

        return "\n".join(lines)

    def _format_sla_status(self) -> str:
        """Format SLA status for reporting"""
        sla_status = self.get_sla_status()

        if sla_status['total_slas'] == 0:
            return "No SLA metrics configured"

        return f"""
Total SLAs: {sla_status['total_slas']}
Compliant: {sla_status['compliant']} ({sla_status['compliant']/sla_status['total_slas']*100:.1f}%)
Warning: {sla_status['warning']} ({sla_status['warning']/sla_status['total_slas']*100:.1f}%)
Non-compliant: {sla_status['non_compliant']} ({sla_status['non_compliant']/sla_status['total_slas']*100:.1f}%)
Overall Compliance Rate: {sla_status['compliance_rate']:.1f}%
"""

    def _generate_recommendations(self) -> str:
        """Generate performance recommendations"""
        recommendations = []

        # System health recommendations
        system_metrics = self.get_metrics_summary(MetricType.SYSTEM_HEALTH, 1)  # Last hour
        if system_metrics['count'] > 0 and system_metrics['average'] > 80:
            recommendations.append("High system resource utilization detected. Consider scaling resources or optimizing performance.")

        # SLA recommendations
        sla_status = self.get_sla_status()
        if sla_status['compliance_rate'] < 95:
            recommendations.append("SLA compliance below target. Review and address non-compliant metrics.")

        # Evidence validation recommendations
        pending_evidence = sum(1 for e in self.evidence_records if e.validation_status == 'pending')
        if pending_evidence > 10:
            recommendations.append(f"High number of pending evidence validations ({pending_evidence}). Prioritize evidence review process.")

        if not recommendations:
            recommendations.append("System performance is within acceptable parameters. Continue monitoring.")

        return "\n".join(f"- {rec}" for rec in recommendations)


class VulnerabilityManagementMetrics:
    """
    Specialized metrics for vulnerability management processes

    Tracks key performance indicators for vulnerability management:
    - Mean Time To Detect (MTTD)
    - Mean Time To Respond (MTTR)
    - Patch deployment rates
    - Vulnerability scan coverage
    - Risk reduction metrics
    """

    def __init__(self, performance_monitor: PerformanceMonitor):
        self.monitor = performance_monitor
        self.vulnerability_data = {
            'total_vulnerabilities': 0,
            'critical_vulnerabilities': 0,
            'patched_vulnerabilities': 0,
            'average_mttd_days': 0,
            'average_mttr_days': 0,
            'scan_coverage_percent': 0
        }

    def update_vulnerability_metrics(self, vulnerabilities: List[Dict[str, Any]]):
        """Update vulnerability management metrics"""
        self.vulnerability_data['total_vulnerabilities'] = len(vulnerabilities)
        self.vulnerability_data['critical_vulnerabilities'] = sum(
            1 for v in vulnerabilities if v.get('severity') == 'critical'
        )
        self.vulnerability_data['patched_vulnerabilities'] = sum(
            1 for v in vulnerabilities if v.get('status') == 'patched'
        )

        # Calculate MTTD and MTTR (simplified)
        detection_times = [v.get('days_to_detect', 7) for v in vulnerabilities if v.get('days_to_detect')]
        response_times = [v.get('days_to_patch', 30) for v in vulnerabilities if v.get('days_to_patch')]

        if detection_times:
            self.vulnerability_data['average_mttd_days'] = statistics.mean(detection_times)
        if response_times:
            self.vulnerability_data['average_mttr_days'] = statistics.mean(response_times)

        # Record metrics
        timestamp = datetime.now(timezone.utc)

        for metric_name, value in self.vulnerability_data.items():
            if isinstance(value, (int, float)):
                self.monitor.record_metric(PerformanceMetric(
                    metric_id=f"vuln_{metric_name}_{int(timestamp.timestamp())}",
                    metric_type=MetricType.VULNERABILITY_MANAGEMENT,
                    name=metric_name.replace('_', ' ').title(),
                    value=float(value),
                    unit="count" if "vulnerabilities" in metric_name else "days" if "days" in metric_name else "percent",
                    timestamp=timestamp,
                    tags={"category": "vulnerability_management"}
                ))

    def get_vulnerability_kpis(self) -> Dict[str, Any]:
        """Get key vulnerability management performance indicators"""
        data = self.vulnerability_data.copy()

        # Calculate additional KPIs
        if data['total_vulnerabilities'] > 0:
            data['patch_rate_percent'] = (data['patched_vulnerabilities'] / data['total_vulnerabilities']) * 100
            data['critical_unpatched'] = data['critical_vulnerabilities'] - sum(
                1 for v in [] if v.get('severity') == 'critical' and v.get('status') == 'patched'  # Would need actual data
            )
        else:
            data['patch_rate_percent'] = 100.0
            data['critical_unpatched'] = 0

        return data


# Global instances
performance_monitor = PerformanceMonitor()
vulnerability_metrics = VulnerabilityManagementMetrics(performance_monitor)


def collect_request_metrics(route: str, response_time: float, status_code: int):
    """Collect metrics for HTTP requests"""
    timestamp = datetime.now(timezone.utc)

    performance_monitor.record_metric(PerformanceMetric(
        metric_id=f"request_{route}_{int(timestamp.timestamp())}",
        metric_type=MetricType.SYSTEM_RESPONSE_TIME,
        name="Request Response Time",
        value=response_time,
        unit="seconds",
        timestamp=timestamp,
        tags={"route": route, "status_code": str(status_code)},
        metadata={"endpoint": route, "http_status": status_code}
    ))


def collect_user_activity_metrics(user_id: str, action: str, resource: str):
    """Collect metrics for user activities"""
    timestamp = datetime.now(timezone.utc)

    performance_monitor.record_metric(PerformanceMetric(
        metric_id=f"user_activity_{user_id}_{int(timestamp.timestamp())}",
        metric_type=MetricType.USER_ACTIVITY,
        name="User Activity",
        value=1.0,  # Count
        unit="actions",
        timestamp=timestamp,
        tags={"user_id": user_id, "action": action, "resource": resource}
    ))


def create_validation_evidence(evidence_type: ValidationEvidenceType, title: str,
                             description: str, source_system: str,
                             evidence_data: Dict[str, Any]) -> ValidationEvidence:
    """Create and record validation evidence"""
    evidence = ValidationEvidence(
        evidence_id=f"evidence_{int(time.time())}_{hash(title) % 10000}",
        evidence_type=evidence_type,
        title=title,
        description=description,
        source_system=source_system,
        collected_at=datetime.now(timezone.utc),
        evidence_data=evidence_data
    )

    performance_monitor.record_evidence(evidence)
    return evidence


def get_performance_dashboard_data() -> Dict[str, Any]:
    """Get data for performance dashboard"""
    return {
        'system_health': performance_monitor.get_metrics_summary(MetricType.SYSTEM_HEALTH),
        'response_times': performance_monitor.get_metrics_summary(MetricType.SYSTEM_RESPONSE_TIME),
        'vulnerability_metrics': vulnerability_metrics.get_vulnerability_kpis(),
        'sla_status': performance_monitor.get_sla_status(),
        'evidence_summary': {
            'total': len(performance_monitor.evidence_records),
            'validated': sum(1 for e in performance_monitor.evidence_records if e.validation_status == 'validated'),
            'pending': sum(1 for e in performance_monitor.evidence_records if e.validation_status == 'pending')
        }
    }


if __name__ == "__main__":
    # Demonstration of performance metrics and validation evidence
    print("Performance Metrics and Validation Evidence Demonstration")
    print("=" * 60)

    # Start monitoring
    print("\nStarting performance monitoring...")
    performance_monitor.start_monitoring()

    # Simulate some metrics collection
    print("Collecting sample metrics...")

    # System metrics (would be collected automatically)
    time.sleep(2)  # Allow monitoring to collect some data

    # Manual metrics
    collect_request_metrics("/vulnerability_management_procedures", 0.234, 200)
    collect_request_metrics("/automated_testing", 1.567, 200)
    collect_user_activity_metrics("user123", "assessment_created", "security_control")

    # Create validation evidence
    test_evidence = create_validation_evidence(
        ValidationEvidenceType.AUTOMATED_TEST_RESULTS,
        "Vulnerability Scan Results",
        "Automated vulnerability scan of web servers",
        "Nessus Scanner",
        {
            "scan_target": "web-server-01",
            "findings": [
                {"vulnerability": "CVE-2023-1234", "severity": "high", "status": "open"},
                {"vulnerability": "CVE-2023-5678", "severity": "medium", "status": "patched"}
            ]
        }
    )

    # Validate evidence
    test_evidence.validate_evidence("Automated Validator")

    # Update vulnerability metrics
    sample_vulnerabilities = [
        {"severity": "critical", "status": "open", "days_to_detect": 5, "days_to_patch": 15},
        {"severity": "high", "status": "patched", "days_to_detect": 3, "days_to_patch": 7},
        {"severity": "medium", "status": "open", "days_to_detect": 10, "days_to_patch": 45}
    ]
    vulnerability_metrics.update_vulnerability_metrics(sample_vulnerabilities)

    # Get dashboard data
    dashboard_data = get_performance_dashboard_data()
    print("\nPerformance Dashboard Data:")
    print(f"System Health Metrics: {dashboard_data['system_health']['count']} readings")
    print(f"Average Response Time: {dashboard_data['response_times'].get('average', 0):.3f}s")
    print(f"Vulnerability KPIs: {dashboard_data['vulnerability_metrics']}")
    print(f"Evidence Summary: {dashboard_data['evidence_summary']}")

    # Generate performance report
    print("\nGenerating Performance Report...")
    report = performance_monitor.generate_performance_report()
    print("Report excerpt:")
    print(report[:1000] + "...\n[Report truncated for display]")

    # Stop monitoring
    print("\nStopping performance monitoring...")
    performance_monitor.stop_monitoring()

    print("\n" + "=" * 60)
    print("Performance metrics and validation evidence demonstration completed!")
    print(f"Collected {len(performance_monitor.metrics)} metrics and {len(performance_monitor.evidence_records)} evidence records")