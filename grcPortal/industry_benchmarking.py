"""
Industry Benchmarking Framework for GRC Portal

This module implements comprehensive industry benchmarking capabilities
for compliance programs, comparing organizational performance against
industry standards and peer organizations.

Key Features:
- Industry standard comparisons
- Peer organization benchmarking
- Compliance maturity assessment
- Performance gap analysis
- Benchmarking reports and analytics

Author: GRC Portal Development Team
"""

import json
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum


class IndustrySector(Enum):
    """Industry sectors for benchmarking"""
    FINANCIAL_SERVICES = "financial_services"
    HEALTHCARE = "healthcare"
    RETAIL = "retail"
    MANUFACTURING = "manufacturing"
    TECHNOLOGY = "technology"
    GOVERNMENT = "government"
    EDUCATION = "education"
    ENERGY = "energy"


class ComplianceFramework(Enum):
    """Compliance frameworks for benchmarking"""
    ISO_27001 = "ISO 27001"
    NIST_CSF = "NIST CSF"
    GDPR = "GDPR"
    HIPAA = "HIPAA"
    PCI_DSS = "PCI DSS"
    SOX = "SOX"
    CIS_CONTROLS = "CIS Controls"


@dataclass
class BenchmarkMetric:
    """Represents a benchmarking metric"""
    metric_id: str
    name: str
    category: str
    unit: str
    industry_average: float
    top_performer: float
    bottom_performer: float
    percentile_25: float
    percentile_75: float
    data_points: int
    last_updated: datetime


@dataclass
class OrganizationBenchmark:
    """Organization's benchmarking data"""
    organization_id: str
    industry_sector: IndustrySector
    compliance_framework: ComplianceFramework
    metric_name: str
    current_value: float
    benchmark_date: datetime
    percentile_rank: Optional[float] = None
    gap_to_average: Optional[float] = None
    gap_to_top: Optional[float] = None
    performance_rating: str = "unknown"  # excellent, good, average, below_average, poor


@dataclass
class BenchmarkReport:
    """Comprehensive benchmarking report"""
    report_id: str
    organization_id: str
    industry_sector: IndustrySector
    compliance_framework: ComplianceFramework
    report_date: datetime
    overall_score: float
    percentile_rank: float
    strengths: List[str]
    weaknesses: List[str]
    recommendations: List[str]
    detailed_metrics: Dict[str, Any]


class IndustryBenchmarkingEngine:
    """
    Main engine for industry benchmarking and comparative analysis

    Provides comprehensive benchmarking against industry standards and peers,
    including gap analysis, performance ratings, and improvement recommendations.
    """

    def __init__(self):
        self.benchmark_data: Dict[str, BenchmarkMetric] = {}
        self.organization_benchmarks: List[OrganizationBenchmark] = []
        self._load_benchmark_data()

    def _load_benchmark_data(self):
        """Load industry benchmark data"""
        # This would typically load from a database or external data source
        # For demonstration, we'll create sample benchmark data
        self._create_sample_benchmark_data()

    def _create_sample_benchmark_data(self):
        """Create sample benchmark data for demonstration"""
        benchmark_metrics = [
            {
                "metric_id": "compliance_score_financial",
                "name": "Overall Compliance Score",
                "category": "compliance",
                "unit": "percentage",
                "industry_average": 78.5,
                "top_performer": 95.2,
                "bottom_performer": 45.1,
                "percentile_25": 65.3,
                "percentile_75": 87.9,
                "data_points": 1250
            },
            {
                "metric_id": "incident_response_time_financial",
                "name": "Mean Time to Respond (Incidents)",
                "category": "incident_response",
                "unit": "hours",
                "industry_average": 4.2,
                "top_performer": 1.1,
                "bottom_performer": 18.7,
                "percentile_25": 2.8,
                "percentile_75": 6.9,
                "data_points": 980
            },
            {
                "metric_id": "vulnerability_patch_rate_financial",
                "name": "Critical Vulnerability Patch Rate",
                "category": "vulnerability_management",
                "unit": "percentage",
                "industry_average": 72.3,
                "top_performer": 98.1,
                "bottom_performer": 23.4,
                "percentile_25": 58.7,
                "percentile_75": 84.2,
                "data_points": 1100
            },
            {
                "metric_id": "audit_findings_financial",
                "name": "Average Audit Findings per Year",
                "category": "audit",
                "unit": "count",
                "industry_average": 12.8,
                "top_performer": 2.1,
                "bottom_performer": 45.6,
                "percentile_25": 8.3,
                "percentile_75": 18.9,
                "data_points": 850
            },
            {
                "metric_id": "training_completion_financial",
                "name": "Security Training Completion Rate",
                "category": "training",
                "unit": "percentage",
                "industry_average": 68.9,
                "top_performer": 97.3,
                "bottom_performer": 34.2,
                "percentile_25": 55.1,
                "percentile_75": 82.4,
                "data_points": 920
            }
        ]

        for metric_data in benchmark_metrics:
            metric = BenchmarkMetric(
                metric_id=metric_data["metric_id"],
                name=metric_data["name"],
                category=metric_data["category"],
                unit=metric_data["unit"],
                industry_average=metric_data["industry_average"],
                top_performer=metric_data["top_performer"],
                bottom_performer=metric_data["bottom_performer"],
                percentile_25=metric_data["percentile_25"],
                percentile_75=metric_data["percentile_75"],
                data_points=metric_data["data_points"],
                last_updated=datetime.now(timezone.utc)
            )
            self.benchmark_data[metric.metric_id] = metric

    def benchmark_organization(self, organization_id: str, industry_sector: IndustrySector,
                             compliance_framework: ComplianceFramework,
                             metrics: Dict[str, float]) -> OrganizationBenchmark:
        """
        Benchmark an organization's performance against industry standards

        Args:
            organization_id: Unique identifier for the organization
            industry_sector: Industry sector for comparison
            compliance_framework: Compliance framework being assessed
            metrics: Dictionary of metric names and values

        Returns:
            OrganizationBenchmark with comparative analysis
        """
        benchmark_results = []

        for metric_name, current_value in metrics.items():
            # Find appropriate benchmark data
            benchmark_key = f"{metric_name.lower().replace(' ', '_')}_{industry_sector.value}"

            if benchmark_key in self.benchmark_data:
                benchmark_metric = self.benchmark_data[benchmark_key]

                # Calculate percentile rank
                percentile_rank = self._calculate_percentile_rank(current_value, benchmark_metric)

                # Calculate gaps
                gap_to_average = current_value - benchmark_metric.industry_average
                gap_to_top = current_value - benchmark_metric.top_performer

                # Determine performance rating
                performance_rating = self._calculate_performance_rating(percentile_rank)

                org_benchmark = OrganizationBenchmark(
                    organization_id=organization_id,
                    industry_sector=industry_sector,
                    compliance_framework=compliance_framework,
                    metric_name=metric_name,
                    current_value=current_value,
                    benchmark_date=datetime.now(timezone.utc),
                    percentile_rank=percentile_rank,
                    gap_to_average=gap_to_average,
                    gap_to_top=gap_to_top,
                    performance_rating=performance_rating
                )

                benchmark_results.append(org_benchmark)
                self.organization_benchmarks.append(org_benchmark)

        # Return the primary benchmark (first metric or average)
        if benchmark_results:
            return benchmark_results[0]  # For simplicity, return first
        else:
            # Return a default benchmark if no matches found
            return OrganizationBenchmark(
                organization_id=organization_id,
                industry_sector=industry_sector,
                compliance_framework=compliance_framework,
                metric_name="overall_compliance",
                current_value=75.0,
                benchmark_date=datetime.now(timezone.utc),
                percentile_rank=65.0,
                performance_rating="average"
            )

    def _calculate_percentile_rank(self, value: float, benchmark: BenchmarkMetric) -> float:
        """Calculate percentile rank for a given value"""
        # Simplified percentile calculation
        if value >= benchmark.top_performer:
            return 95.0
        elif value <= benchmark.bottom_performer:
            return 5.0
        elif value >= benchmark.percentile_75:
            return 75.0 + (value - benchmark.percentile_75) / (benchmark.top_performer - benchmark.percentile_75) * 20
        elif value >= benchmark.percentile_25:
            return 25.0 + (value - benchmark.percentile_25) / (benchmark.percentile_75 - benchmark.percentile_25) * 50
        else:
            return 5.0 + (value - benchmark.bottom_performer) / (benchmark.percentile_25 - benchmark.bottom_performer) * 20

    def _calculate_performance_rating(self, percentile_rank: float) -> str:
        """Calculate performance rating based on percentile rank"""
        if percentile_rank >= 90:
            return "excellent"
        elif percentile_rank >= 75:
            return "good"
        elif percentile_rank >= 50:
            return "average"
        elif percentile_rank >= 25:
            return "below_average"
        else:
            return "poor"

    def generate_benchmark_report(self, organization_id: str, industry_sector: IndustrySector,
                                compliance_framework: ComplianceFramework) -> BenchmarkReport:
        """
        Generate a comprehensive benchmarking report

        Args:
            organization_id: Organization identifier
            industry_sector: Industry sector
            compliance_framework: Compliance framework

        Returns:
            Comprehensive benchmark report
        """
        # Get organization's benchmarks
        org_benchmarks = [b for b in self.organization_benchmarks
                         if b.organization_id == organization_id and
                         b.industry_sector == industry_sector and
                         b.compliance_framework == compliance_framework]

        if not org_benchmarks:
            # Generate sample benchmarks for demonstration
            sample_metrics = {
                "Overall Compliance Score": 82.5,
                "Mean Time to Respond": 3.8,
                "Critical Vulnerability Patch Rate": 76.2,
                "Audit Findings per Year": 9.3,
                "Security Training Completion": 71.8
            }

            for metric_name, value in sample_metrics.items():
                self.benchmark_organization(organization_id, industry_sector,
                                          compliance_framework, {metric_name: value})

            org_benchmarks = [b for b in self.organization_benchmarks
                             if b.organization_id == organization_id]

        # Calculate overall scores
        if org_benchmarks:
            avg_percentile = sum(b.percentile_rank or 50 for b in org_benchmarks) / len(org_benchmarks)
            overall_score = sum(b.current_value for b in org_benchmarks) / len(org_benchmarks)
        else:
            avg_percentile = 50.0
            overall_score = 75.0

        # Identify strengths and weaknesses
        strengths = []
        weaknesses = []

        for benchmark in org_benchmarks:
            if benchmark.performance_rating in ["excellent", "good"]:
                strengths.append(f"Strong performance in {benchmark.metric_name}")
            elif benchmark.performance_rating in ["below_average", "poor"]:
                weaknesses.append(f"Needs improvement in {benchmark.metric_name}")

        # Generate recommendations
        recommendations = self._generate_benchmark_recommendations(org_benchmarks, industry_sector)

        # Detailed metrics
        detailed_metrics = {}
        for benchmark in org_benchmarks:
            benchmark_metric = None
            for key, metric in self.benchmark_data.items():
                if benchmark.metric_name.lower().replace(" ", "_") in key:
                    benchmark_metric = metric
                    break

            detailed_metrics[benchmark.metric_name] = {
                "current_value": benchmark.current_value,
                "industry_average": benchmark_metric.industry_average if benchmark_metric else 0,
                "percentile_rank": benchmark.percentile_rank,
                "performance_rating": benchmark.performance_rating,
                "gap_to_average": benchmark.gap_to_average,
                "gap_to_top": benchmark.gap_to_top
            }

        return BenchmarkReport(
            report_id=f"benchmark_{organization_id}_{int(datetime.now(timezone.utc).timestamp())}",
            organization_id=organization_id,
            industry_sector=industry_sector,
            compliance_framework=compliance_framework,
            report_date=datetime.now(timezone.utc),
            overall_score=overall_score,
            percentile_rank=avg_percentile,
            strengths=strengths,
            weaknesses=weaknesses,
            recommendations=recommendations,
            detailed_metrics=detailed_metrics
        )

    def _generate_benchmark_recommendations(self, benchmarks: List[OrganizationBenchmark],
                                          industry_sector: IndustrySector) -> List[str]:
        """Generate improvement recommendations based on benchmark results"""
        recommendations = []

        for benchmark in benchmarks:
            if benchmark.performance_rating == "poor":
                recommendations.append(f"Urgent: Significantly improve {benchmark.metric_name} - currently {benchmark.percentile_rank:.1f} percentile")
            elif benchmark.performance_rating == "below_average":
                recommendations.append(f"Improve {benchmark.metric_name} to reach industry average - currently {benchmark.percentile_rank:.1f} percentile")
            elif benchmark.performance_rating == "average":
                recommendations.append(f"Consider enhancing {benchmark.metric_name} to reach top quartile performance")
            elif benchmark.performance_rating == "good":
                recommendations.append(f"Maintain strong performance in {benchmark.metric_name}")
            elif benchmark.performance_rating == "excellent":
                recommendations.append(f"Share best practices for {benchmark.metric_name} with industry peers")

        # Add industry-specific recommendations
        if industry_sector == IndustrySector.FINANCIAL_SERVICES:
            recommendations.append("Consider implementing advanced fraud detection systems to stay ahead of industry trends")
        elif industry_sector == IndustrySector.HEALTHCARE:
            recommendations.append("Focus on HIPAA compliance automation to reduce manual audit efforts")
        elif industry_sector == IndustrySector.TECHNOLOGY:
            recommendations.append("Invest in DevSecOps practices to improve vulnerability management")

        return recommendations

    def get_industry_averages(self, industry_sector: IndustrySector) -> Dict[str, Any]:
        """Get industry average metrics for a sector"""
        sector_metrics = {}
        sector_prefix = f"_{industry_sector.value}"

        for key, metric in self.benchmark_data.items():
            if key.endswith(sector_prefix):
                metric_name = key.replace(sector_prefix, "").replace("_", " ").title()
                sector_metrics[metric_name] = {
                    "average": metric.industry_average,
                    "top_performer": metric.top_performer,
                    "percentile_25": metric.percentile_25,
                    "percentile_75": metric.percentile_75,
                    "data_points": metric.data_points
                }

        return sector_metrics

    def compare_to_peers(self, organization_id: str, metric_name: str,
                        peer_organizations: List[str]) -> Dict[str, Any]:
        """Compare organization performance to specific peer organizations"""
        # This would typically query peer data from a database
        # For demonstration, return mock comparison data

        comparison = {
            "organization_id": organization_id,
            "metric_name": metric_name,
            "peer_comparison": {},
            "rank_among_peers": 0,
            "percentile_among_peers": 0.0
        }

        # Mock peer data
        peer_data = {}
        for peer in peer_organizations:
            peer_data[peer] = {
                "value": 70 + (hash(peer) % 30),  # Random value between 70-100
                "rank": 0
            }

        # Add organization's data
        org_value = 75  # Mock value
        peer_data[organization_id] = {"value": org_value, "rank": 0}

        # Sort by value (descending for scores, ascending for times/costs)
        sorted_peers = sorted(peer_data.items(), key=lambda x: x[1]["value"], reverse=True)

        # Assign ranks
        for rank, (peer_id, data) in enumerate(sorted_peers, 1):
            data["rank"] = rank
            comparison["peer_comparison"][peer_id] = {
                "value": data["value"],
                "rank": data["rank"]
            }

        org_rank = peer_data[organization_id]["rank"]
        comparison["rank_among_peers"] = org_rank
        comparison["percentile_among_peers"] = ((len(peer_organizations) + 1 - org_rank) / (len(peer_organizations) + 1)) * 100

        return comparison


# Global instance
benchmarking_engine = IndustryBenchmarkingEngine()


def get_industry_benchmark_report(organization_id: str, industry_sector: str,
                                compliance_framework: str) -> Dict[str, Any]:
    """Get industry benchmark report for an organization"""
    try:
        sector = IndustrySector(industry_sector)
        framework = ComplianceFramework(compliance_framework)

        report = benchmarking_engine.generate_benchmark_report(organization_id, sector, framework)
        return {
            "success": True,
            "report": {
                "report_id": report.report_id,
                "overall_score": report.overall_score,
                "percentile_rank": report.percentile_rank,
                "strengths": report.strengths,
                "weaknesses": report.weaknesses,
                "recommendations": report.recommendations,
                "detailed_metrics": report.detailed_metrics
            }
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


if __name__ == "__main__":
    # Demonstration of industry benchmarking
    print("Industry Benchmarking Demonstration")
    print("=" * 50)

    # Example benchmarking
    metrics = {
        "Overall Compliance Score": 82.5,
        "Mean Time to Respond": 3.8,
        "Critical Vulnerability Patch Rate": 76.2
    }

    benchmark = benchmarking_engine.benchmark_organization(
        "org_123",
        IndustrySector.FINANCIAL_SERVICES,
        ComplianceFramework.ISO_27001,
        metrics
    )

    print(f"Organization Benchmark Results:")
    print(f"Metric: {benchmark.metric_name}")
    print(f"Current Value: {benchmark.current_value}")
    print(f"Percentile Rank: {benchmark.percentile_rank:.1f}")
    print(f"Performance Rating: {benchmark.performance_rating}")
    print(f"Gap to Industry Average: {benchmark.gap_to_average:.2f}")

    # Generate full report
    report = benchmarking_engine.generate_benchmark_report(
        "org_123",
        IndustrySector.FINANCIAL_SERVICES,
        ComplianceFramework.ISO_27001
    )

    print(f"\nBenchmark Report Summary:")
    print(f"Overall Score: {report.overall_score:.1f}")
    print(f"Percentile Rank: {report.percentile_rank:.1f}%")
    print(f"Strengths: {len(report.strengths)}")
    print(f"Weaknesses: {len(report.weaknesses)}")
    print(f"Recommendations: {len(report.recommendations)}")