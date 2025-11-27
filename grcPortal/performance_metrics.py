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
import numpy as np
from sklearn.linear_model import LinearRegression
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pandas as pd


class MetricType(Enum):
    """Types of performance metrics"""
    VULNERABILITY_MANAGEMENT = "vulnerability_management"
    ASSESSMENT_PERFORMANCE = "assessment_performance"
    SYSTEM_RESPONSE_TIME = "system_response_time"
    USER_ACTIVITY = "user_activity"
    COMPLIANCE_VALIDATION = "compliance_validation"
    SECURITY_CONTROL_EFFECTIVENESS = "security_control_effectiveness"
    SYSTEM_HEALTH = "system_health"
    PREDICTIVE_ANALYTICS = "predictive_analytics"
    CONTINUOUS_IMPROVEMENT = "continuous_improvement"
    RISK_MANAGEMENT = "risk_management"
    INCIDENT_RESPONSE = "incident_response"
    COMPLIANCE_MONITORING = "compliance_monitoring"


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

        # Predictive recommendations
        predictive_insights = self.get_predictive_insights()
        if predictive_insights.get('anomalies_detected', 0) > 0:
            recommendations.append(f"Anomalies detected in {predictive_insights['anomalies_detected']} metrics. Review anomaly details for potential issues.")

        forecast_data = self.get_performance_forecast(hours_ahead=24)
        if forecast_data.get('risk_level') == 'high':
            recommendations.append("Performance forecast indicates potential issues in the next 24 hours. Prepare contingency plans.")

        if not recommendations:
            recommendations.append("System performance is within acceptable parameters. Continue monitoring.")

        return "\n".join(f"- {rec}" for rec in recommendations)

    def get_predictive_insights(self, time_range_hours: int = 24) -> Dict[str, Any]:
        """Generate predictive insights using historical data"""
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=time_range_hours)

        # Filter recent metrics
        recent_metrics = [m for m in self.metrics if m.timestamp >= cutoff_time]

        if len(recent_metrics) < 10:
            return {"error": "Insufficient data for predictive analysis"}

        insights = {
            "anomalies_detected": 0,
            "trend_analysis": {},
            "forecast_accuracy": 0.0,
            "risk_indicators": []
        }

        # Group metrics by type and name
        metric_groups = {}
        for metric in recent_metrics:
            key = f"{metric.metric_type.value}_{metric.name}"
            if key not in metric_groups:
                metric_groups[key] = []
            metric_groups[key].append(metric)

        # Analyze each metric group
        for metric_key, metrics in metric_groups.items():
            if len(metrics) < 5:
                continue

            # Sort by timestamp
            metrics.sort(key=lambda m: m.timestamp)

            # Extract values and timestamps
            values = np.array([m.value for m in metrics])
            timestamps = np.array([(m.timestamp - metrics[0].timestamp).total_seconds() / 3600 for m in metrics])

            # Anomaly detection
            if len(values) >= 10:
                try:
                    # Use Isolation Forest for anomaly detection
                    iso_forest = IsolationForest(contamination=0.1, random_state=42)
                    anomalies = iso_forest.fit_predict(values.reshape(-1, 1))
                    anomaly_count = sum(1 for a in anomalies if a == -1)
                    insights["anomalies_detected"] += anomaly_count

                    if anomaly_count > 0:
                        insights["risk_indicators"].append({
                            "metric": metric_key,
                            "anomalies": anomaly_count,
                            "severity": "high" if anomaly_count > len(values) * 0.2 else "medium"
                        })
                except Exception as e:
                    print(f"Error in anomaly detection for {metric_key}: {e}")

            # Trend analysis
            if len(values) >= 3:
                try:
                    # Simple linear regression for trend
                    X = timestamps.reshape(-1, 1)
                    y = values
                    reg = LinearRegression()
                    reg.fit(X, y)

                    slope = reg.coef_[0]
                    trend = "increasing" if slope > 0.01 else "decreasing" if slope < -0.01 else "stable"

                    insights["trend_analysis"][metric_key] = {
                        "trend": trend,
                        "slope": slope,
                        "r_squared": reg.score(X, y)
                    }
                except Exception as e:
                    print(f"Error in trend analysis for {metric_key}: {e}")

        return insights

    def get_performance_forecast(self, hours_ahead: int = 24) -> Dict[str, Any]:
        """Generate performance forecast for upcoming period"""
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=168)  # Last 7 days

        # Filter recent metrics
        recent_metrics = [m for m in self.metrics if m.timestamp >= cutoff_time]

        if len(recent_metrics) < 20:
            return {"error": "Insufficient historical data for forecasting"}

        forecast = {
            "forecast_period_hours": hours_ahead,
            "predictions": {},
            "risk_level": "low",
            "confidence_intervals": {}
        }

        # Group and forecast each metric type
        metric_groups = {}
        for metric in recent_metrics:
            key = f"{metric.metric_type.value}_{metric.name}"
            if key not in metric_groups:
                metric_groups[key] = []
            metric_groups[key].append(metric)

        risk_score = 0

        for metric_key, metrics in metric_groups.items():
            if len(metrics) < 10:
                continue

            # Sort by timestamp
            metrics.sort(key=lambda m: m.timestamp)

            # Prepare time series data
            timestamps = np.array([(m.timestamp - metrics[0].timestamp).total_seconds() / 3600 for m in metrics])
            values = np.array([m.value for m in metrics])

            try:
                # Linear regression for forecasting
                X = timestamps.reshape(-1, 1)
                y = values

                reg = LinearRegression()
                reg.fit(X, y)

                # Forecast future values
                future_times = np.array([timestamps[-1] + i for i in range(1, hours_ahead + 1)]).reshape(-1, 1)
                predictions = reg.predict(future_times)

                forecast["predictions"][metric_key] = {
                    "forecasted_values": predictions.tolist(),
                    "trend": "increasing" if reg.coef_[0] > 0 else "decreasing",
                    "confidence": reg.score(X, y)
                }

                # Risk assessment based on forecast
                if metric_key.endswith("_CPU Usage") and np.mean(predictions) > 85:
                    risk_score += 2
                elif metric_key.endswith("_Memory Usage") and np.mean(predictions) > 90:
                    risk_score += 2
                elif metric_key.endswith("_Disk Usage") and np.mean(predictions) > 95:
                    risk_score += 3

            except Exception as e:
                print(f"Error forecasting {metric_key}: {e}")

        # Determine overall risk level
        if risk_score >= 5:
            forecast["risk_level"] = "high"
        elif risk_score >= 2:
            forecast["risk_level"] = "medium"
        else:
            forecast["risk_level"] = "low"

        return forecast

    def get_automated_review_recommendations(self) -> List[Dict[str, Any]]:
        """Generate automated review recommendations based on performance data"""
        recommendations = []

        # Analyze SLA compliance
        sla_status = self.get_sla_status()
        if sla_status['compliance_rate'] < 95:
            recommendations.append({
                "type": "sla_review",
                "priority": "high",
                "title": "SLA Compliance Review Required",
                "description": f"SLA compliance rate is {sla_status['compliance_rate']:.1f}%. Review non-compliant metrics.",
                "action_items": [
                    "Review SLA targets and actual performance",
                    "Identify root causes of non-compliance",
                    "Develop remediation plans",
                    "Schedule follow-up reviews"
                ]
            })

        # Analyze evidence validation backlog
        pending_evidence = sum(1 for e in self.evidence_records if e.validation_status == 'pending')
        if pending_evidence > 5:
            recommendations.append({
                "type": "evidence_review",
                "priority": "medium",
                "title": "Evidence Validation Backlog",
                "description": f"{pending_evidence} evidence records pending validation.",
                "action_items": [
                    "Prioritize critical evidence validation",
                    "Allocate additional review resources",
                    "Implement automated validation where possible",
                    "Review validation criteria and processes"
                ]
            })

        # Analyze system health trends
        predictive_insights = self.get_predictive_insights()
        anomalies = predictive_insights.get('anomalies_detected', 0)
        if anomalies > 0:
            recommendations.append({
                "type": "anomaly_investigation",
                "priority": "high" if anomalies > 3 else "medium",
                "title": "System Anomalies Detected",
                "description": f"{anomalies} anomalous patterns detected in system metrics.",
                "action_items": [
                    "Investigate root causes of anomalies",
                    "Review system configuration changes",
                    "Implement additional monitoring",
                    "Document findings and remediation steps"
                ]
            })

        # Analyze performance trends
        forecast = self.get_performance_forecast()
        if forecast.get('risk_level') in ['medium', 'high']:
            recommendations.append({
                "type": "performance_forecast_review",
                "priority": forecast.get('risk_level'),
                "title": "Performance Forecast Review",
                "description": f"Performance forecast indicates {forecast.get('risk_level')} risk for next {forecast.get('forecast_period_hours')} hours.",
                "action_items": [
                    "Review forecast predictions and assumptions",
                    "Prepare contingency plans",
                    "Schedule additional monitoring",
                    "Communicate risks to stakeholders"
                ]
            })

        return recommendations


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


class AdvancedKPIFramework:
    """
    Advanced KPI Framework for comprehensive performance measurement

    Provides sophisticated KPI calculations, trend analysis, and performance
    benchmarking for enterprise compliance programs.
    """

    def __init__(self, performance_monitor: PerformanceMonitor):
        self.monitor = performance_monitor
        self.kpi_definitions = self._load_kpi_definitions()
        self.kpi_history = {}  # Store historical KPI values

    def _load_kpi_definitions(self) -> Dict[str, Dict[str, Any]]:
        """Load comprehensive KPI definitions"""
        return {
            "compliance_maturity_score": {
                "name": "Compliance Maturity Score",
                "category": "compliance",
                "calculation_method": "weighted_average",
                "weights": {
                    "policy_completeness": 0.2,
                    "control_implementation": 0.3,
                    "monitoring_effectiveness": 0.25,
                    "audit_performance": 0.15,
                    "continuous_improvement": 0.1
                },
                "target": 85.0,
                "unit": "score",
                "frequency": "monthly"
            },
            "risk_reduction_efficiency": {
                "name": "Risk Reduction Efficiency",
                "category": "risk_management",
                "calculation_method": "ratio",
                "formula": "(risks_mitigated / total_risks_identified) * (1 / average_resolution_time_days)",
                "target": 0.75,
                "unit": "efficiency_ratio",
                "frequency": "quarterly"
            },
            "incident_response_maturity": {
                "name": "Incident Response Maturity",
                "category": "incident_response",
                "calculation_method": "composite",
                "components": ["detection_time", "containment_time", "recovery_time", "post_incident_review"],
                "weights": [0.25, 0.25, 0.25, 0.25],
                "target": 90.0,
                "unit": "maturity_score",
                "frequency": "monthly"
            },
            "predictive_accuracy": {
                "name": "Predictive Analytics Accuracy",
                "category": "predictive_analytics",
                "calculation_method": "accuracy",
                "formula": "correct_predictions / total_predictions",
                "target": 0.85,
                "unit": "percentage",
                "frequency": "weekly"
            },
            "continuous_improvement_velocity": {
                "name": "Continuous Improvement Velocity",
                "category": "continuous_improvement",
                "calculation_method": "velocity",
                "formula": "improvements_implemented / time_period_months",
                "target": 3.0,
                "unit": "improvements_per_month",
                "frequency": "monthly"
            },
            "automation_maturity": {
                "name": "Process Automation Maturity",
                "category": "automation",
                "calculation_method": "percentage",
                "formula": "automated_processes / total_processes",
                "target": 70.0,
                "unit": "percentage",
                "frequency": "quarterly"
            },
            "stakeholder_satisfaction": {
                "name": "Stakeholder Satisfaction Index",
                "category": "stakeholder_management",
                "calculation_method": "survey_based",
                "components": ["communication_effectiveness", "service_quality", "responsiveness", "transparency"],
                "target": 4.2,
                "unit": "rating_out_of_5",
                "frequency": "quarterly"
            },
            "compliance_cost_efficiency": {
                "name": "Compliance Cost Efficiency",
                "category": "financial",
                "calculation_method": "ratio",
                "formula": "compliance_maturity_score / compliance_cost_per_million_revenue",
                "target": 2.0,
                "unit": "efficiency_ratio",
                "frequency": "quarterly"
            }
        }

    def calculate_advanced_kpis(self) -> Dict[str, Dict[str, Any]]:
        """Calculate all advanced KPIs"""
        kpis = {}

        for kpi_id, definition in self.kpi_definitions.items():
            try:
                kpi_value = self._calculate_kpi_value(kpi_id, definition)
                trend = self._calculate_kpi_trend(kpi_id, kpi_value)
                status = self._determine_kpi_status(kpi_value, definition["target"])

                kpis[kpi_id] = {
                    "name": definition["name"],
                    "value": kpi_value,
                    "target": definition["target"],
                    "unit": definition["unit"],
                    "trend": trend,
                    "status": status,
                    "last_updated": datetime.now(timezone.utc),
                    "category": definition["category"]
                }

                # Store in history
                if kpi_id not in self.kpi_history:
                    self.kpi_history[kpi_id] = []
                self.kpi_history[kpi_id].append({
                    "value": kpi_value,
                    "timestamp": datetime.now(timezone.utc)
                })

                # Keep only last 12 months of history
                cutoff = datetime.now(timezone.utc) - timedelta(days=365)
                self.kpi_history[kpi_id] = [
                    h for h in self.kpi_history[kpi_id]
                    if h["timestamp"] > cutoff
                ][:52]  # Max 52 weeks

            except Exception as e:
                print(f"Error calculating KPI {kpi_id}: {e}")
                kpis[kpi_id] = {
                    "name": definition["name"],
                    "value": None,
                    "target": definition["target"],
                    "unit": definition["unit"],
                    "trend": "unknown",
                    "status": "error",
                    "error": str(e),
                    "category": definition["category"]
                }

        return kpis

    def _calculate_kpi_value(self, kpi_id: str, definition: Dict[str, Any]) -> float:
        """Calculate the value for a specific KPI"""
        method = definition["calculation_method"]

        if method == "weighted_average":
            return self._calculate_weighted_average_kpi(definition)
        elif method == "ratio":
            return self._calculate_ratio_kpi(definition)
        elif method == "composite":
            return self._calculate_composite_kpi(definition)
        elif method == "accuracy":
            return self._calculate_accuracy_kpi(definition)
        elif method == "velocity":
            return self._calculate_velocity_kpi(definition)
        elif method == "percentage":
            return self._calculate_percentage_kpi(definition)
        elif method == "survey_based":
            return self._calculate_survey_based_kpi(definition)
        else:
            # Default to mock calculation for demonstration
            return self._calculate_mock_kpi(kpi_id)

    def _calculate_weighted_average_kpi(self, definition: Dict[str, Any]) -> float:
        """Calculate weighted average KPI"""
        weights = definition["weights"]
        weighted_sum = 0.0
        total_weight = 0.0

        for component, weight in weights.items():
            # Get component value from metrics (simplified)
            component_value = self._get_component_value(component)
            weighted_sum += component_value * weight
            total_weight += weight

        return weighted_sum / total_weight if total_weight > 0 else 0.0

    def _calculate_ratio_kpi(self, definition: Dict[str, Any]) -> float:
        """Calculate ratio-based KPI"""
        # Simplified ratio calculation
        numerator = self._get_metric_value("risks_mitigated", 15)
        denominator = self._get_metric_value("total_risks_identified", 20)
        time_factor = 1.0 / max(self._get_metric_value("average_resolution_time_days", 30), 1)

        return (numerator / denominator) * time_factor if denominator > 0 else 0.0

    def _calculate_composite_kpi(self, definition: Dict[str, Any]) -> float:
        """Calculate composite KPI"""
        components = definition["components"]
        weights = definition.get("weights", [1.0/len(components)] * len(components))

        composite_score = 0.0
        for i, component in enumerate(components):
            component_value = self._get_component_value(component)
            weight = weights[i] if i < len(weights) else 1.0/len(components)
            composite_score += component_value * weight

        return composite_score

    def _calculate_accuracy_kpi(self, definition: Dict[str, Any]) -> float:
        """Calculate accuracy-based KPI"""
        correct_predictions = self._get_metric_value("correct_predictions", 85)
        total_predictions = self._get_metric_value("total_predictions", 100)

        return correct_predictions / total_predictions if total_predictions > 0 else 0.0

    def _calculate_velocity_kpi(self, definition: Dict[str, Any]) -> float:
        """Calculate velocity-based KPI"""
        improvements = self._get_metric_value("improvements_implemented", 12)
        time_period = self._get_metric_value("time_period_months", 12)

        return improvements / time_period if time_period > 0 else 0.0

    def _calculate_percentage_kpi(self, definition: Dict[str, Any]) -> float:
        """Calculate percentage-based KPI"""
        automated = self._get_metric_value("automated_processes", 21)
        total = self._get_metric_value("total_processes", 30)

        return (automated / total * 100) if total > 0 else 0.0

    def _calculate_survey_based_kpi(self, definition: Dict[str, Any]) -> float:
        """Calculate survey-based KPI"""
        # Mock survey results
        components = definition.get("components", [])
        return sum(self._get_component_value(comp) for comp in components) / len(components) if components else 4.0

    def _calculate_mock_kpi(self, kpi_id: str) -> float:
        """Calculate mock KPI values for demonstration"""
        mock_values = {
            "compliance_maturity_score": 78.5,
            "risk_reduction_efficiency": 0.68,
            "incident_response_maturity": 82.3,
            "predictive_accuracy": 0.87,
            "continuous_improvement_velocity": 2.8,
            "automation_maturity": 65.4,
            "stakeholder_satisfaction": 4.1,
            "compliance_cost_efficiency": 1.9
        }
        return mock_values.get(kpi_id, 75.0)

    def _get_component_value(self, component: str) -> float:
        """Get value for a KPI component"""
        component_mapping = {
            "policy_completeness": 85.0,
            "control_implementation": 78.0,
            "monitoring_effectiveness": 82.0,
            "audit_performance": 79.0,
            "continuous_improvement": 74.0,
            "detection_time": 88.0,
            "containment_time": 85.0,
            "recovery_time": 80.0,
            "post_incident_review": 87.0,
            "communication_effectiveness": 4.2,
            "service_quality": 4.0,
            "responsiveness": 4.1,
            "transparency": 3.9
        }
        return component_mapping.get(component, 75.0)

    def _get_metric_value(self, metric_name: str, default: float) -> float:
        """Get metric value from performance monitor"""
        # Try to get from actual metrics first
        summary = self.monitor.get_metrics_summary()
        if summary.get("latest"):
            # Simplified - in production would match by name
            return summary["latest"].get("value", default)

        return default

    def _calculate_kpi_trend(self, kpi_id: str, current_value: float) -> str:
        """Calculate KPI trend based on historical data"""
        if kpi_id not in self.kpi_history or len(self.kpi_history[kpi_id]) < 2:
            return "stable"

        history = self.kpi_history[kpi_id][-4:]  # Last 4 measurements
        if len(history) < 2:
            return "stable"

        values = [h["value"] for h in history]
        slope = (values[-1] - values[0]) / len(values)

        if slope > 1.0:
            return "increasing"
        elif slope < -1.0:
            return "decreasing"
        else:
            return "stable"

    def _determine_kpi_status(self, value: float, target: float) -> str:
        """Determine KPI status relative to target"""
        if value is None:
            return "unknown"

        ratio = value / target if target > 0 else 1.0

        if ratio >= 1.0:
            return "on_target"
        elif ratio >= 0.9:
            return "near_target"
        elif ratio >= 0.75:
            return "below_target"
        else:
            return "significantly_below"

    def get_kpi_dashboard_data(self) -> Dict[str, Any]:
        """Get KPI dashboard data"""
        kpis = self.calculate_advanced_kpis()

        # Group KPIs by category
        categories = {}
        for kpi_id, data in kpis.items():
            category = data["category"]
            if category not in categories:
                categories[category] = []
            categories[category].append(data)

        # Calculate category averages
        category_summary = {}
        for category, category_kpis in categories.items():
            valid_kpis = [k for k in category_kpis if k["value"] is not None]
            if valid_kpis:
                avg_value = sum(k["value"] for k in valid_kpis) / len(valid_kpis)
                avg_target = sum(k["target"] for k in valid_kpis) / len(valid_kpis)
                on_target = sum(1 for k in valid_kpis if k["status"] == "on_target")
                category_summary[category] = {
                    "average_score": avg_value,
                    "average_target": avg_target,
                    "on_target_percentage": (on_target / len(valid_kpis)) * 100,
                    "kpi_count": len(valid_kpis)
                }

        return {
            "kpis": kpis,
            "categories": categories,
            "category_summary": category_summary,
            "overall_summary": {
                "total_kpis": len(kpis),
                "on_target_kpis": sum(1 for k in kpis.values() if k["status"] == "on_target"),
                "average_performance": sum(k["value"] or 0 for k in kpis.values()) / len(kpis)
            }
        }


# Global instances
performance_monitor = PerformanceMonitor()
vulnerability_metrics = VulnerabilityManagementMetrics(performance_monitor)
kpi_framework = AdvancedKPIFramework(performance_monitor)


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
        },
        'predictive_insights': performance_monitor.get_predictive_insights(),
        'performance_forecast': performance_monitor.get_performance_forecast(),
        'automated_reviews': performance_monitor.get_automated_review_recommendations(),
        'advanced_kpis': kpi_framework.get_kpi_dashboard_data()
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