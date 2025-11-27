"""
Continuous Improvement Program for GRC Portal

This module implements a comprehensive continuous improvement program
with documented methodology, measurable results, and systematic tracking
of improvement initiatives for enterprise compliance programs.

Key Features:
- PDCA cycle implementation
- Improvement initiative tracking
- Impact measurement and ROI calculation
- Stakeholder engagement and communication
- Lessons learned documentation
- Success metrics and reporting

Author: GRC Portal Development Team
"""

import json
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum


class ImprovementPhase(Enum):
    """Phases of the PDCA cycle"""
    PLAN = "plan"
    DO = "do"
    CHECK = "check"
    ACT = "act"


class ImprovementStatus(Enum):
    """Status of improvement initiatives"""
    IDENTIFIED = "identified"
    PLANNED = "planned"
    IMPLEMENTING = "implementing"
    TESTING = "testing"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    ON_HOLD = "on_hold"


class ImprovementCategory(Enum):
    """Categories of improvement initiatives"""
    PROCESS_OPTIMIZATION = "process_optimization"
    TECHNOLOGY_ENHANCEMENT = "technology_enhancement"
    TRAINING_DEVELOPMENT = "training_development"
    COMPLIANCE_AUTOMATION = "compliance_automation"
    RISK_MANAGEMENT = "risk_management"
    INCIDENT_RESPONSE = "incident_response"
    AUDIT_EFFICIENCY = "audit_efficiency"
    STAKEHOLDER_ENGAGEMENT = "stakeholder_engagement"


@dataclass
class ImprovementInitiative:
    """Represents a continuous improvement initiative"""
    initiative_id: str
    title: str
    description: str
    category: ImprovementCategory
    phase: ImprovementPhase
    status: ImprovementStatus
    priority: str  # high, medium, low
    created_date: datetime
    target_completion_date: Optional[datetime] = None
    actual_completion_date: Optional[datetime] = None
    owner: str
    stakeholders: List[str] = None
    objectives: List[str] = None
    success_criteria: List[str] = None
    current_phase_details: Dict[str, Any] = None
    resources_required: Dict[str, Any] = None
    risks_and_barriers: List[str] = None
    lessons_learned: List[str] = None
    impact_measurements: Dict[str, Any] = None
    roi_analysis: Dict[str, Any] = None

    def __post_init__(self):
        if self.stakeholders is None:
            self.stakeholders = []
        if self.objectives is None:
            self.objectives = []
        if self.success_criteria is None:
            self.success_criteria = []
        if self.current_phase_details is None:
            self.current_phase_details = {}
        if self.resources_required is None:
            self.resources_required = {}
        if self.risks_and_barriers is None:
            self.risks_and_barriers = []
        if self.lessons_learned is None:
            self.lessons_learned = []
        if self.impact_measurements is None:
            self.impact_measurements = {}
        if self.roi_analysis is None:
            self.roi_analysis = {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        data['category'] = self.category.value
        data['phase'] = self.phase.value
        data['status'] = self.status.value
        data['created_date'] = self.created_date.isoformat()
        if self.target_completion_date:
            data['target_completion_date'] = self.target_completion_date.isoformat()
        if self.actual_completion_date:
            data['actual_completion_date'] = self.actual_completion_date.isoformat()
        return data

    def advance_phase(self, new_details: Dict[str, Any] = None):
        """Advance to the next phase in PDCA cycle"""
        phase_order = [ImprovementPhase.PLAN, ImprovementPhase.DO, ImprovementPhase.CHECK, ImprovementPhase.ACT]

        try:
            current_index = phase_order.index(self.phase)
            if current_index < len(phase_order) - 1:
                self.phase = phase_order[current_index + 1]
                if new_details:
                    self.current_phase_details.update(new_details)
        except ValueError:
            pass  # Phase not in standard cycle

    def calculate_progress_percentage(self) -> float:
        """Calculate overall progress percentage"""
        phase_weights = {
            ImprovementPhase.PLAN: 0.1,
            ImprovementPhase.DO: 0.4,
            ImprovementPhase.CHECK: 0.3,
            ImprovementPhase.ACT: 0.2
        }

        base_progress = phase_weights.get(self.phase, 0.0)

        # Add status-based progress
        status_progress = {
            ImprovementStatus.IDENTIFIED: 0.0,
            ImprovementStatus.PLANNED: 0.2,
            ImprovementStatus.IMPLEMENTING: 0.6,
            ImprovementStatus.TESTING: 0.8,
            ImprovementStatus.COMPLETED: 1.0,
            ImprovementStatus.CANCELLED: 0.0,
            ImprovementStatus.ON_HOLD: 0.0
        }

        status_modifier = status_progress.get(self.status, 0.0)

        return min(100.0, (base_progress + status_modifier) * 50)  # Scale to 0-100


@dataclass
class ImprovementMeasurement:
    """Represents impact measurements for improvement initiatives"""
    measurement_id: str
    initiative_id: str
    metric_name: str
    baseline_value: float
    target_value: float
    current_value: Optional[float] = None
    measurement_date: datetime
    unit: str
    improvement_percentage: Optional[float] = None

    def calculate_improvement(self):
        """Calculate improvement percentage"""
        if self.current_value is not None and self.baseline_value != 0:
            self.improvement_percentage = ((self.current_value - self.baseline_value) / abs(self.baseline_value)) * 100


class ContinuousImprovementProgram:
    """
    Main continuous improvement program management system

    Implements PDCA methodology with comprehensive tracking, measurement,
    and reporting capabilities for systematic improvement initiatives.
    """

    def __init__(self):
        self.initiatives: List[ImprovementInitiative] = []
        self.measurements: List[ImprovementMeasurement] = []
        self.improvement_backlog: List[Dict[str, Any]] = []
        self._load_sample_data()

    def _load_sample_data(self):
        """Load sample improvement initiatives for demonstration"""
        sample_initiatives = [
            {
                "initiative_id": "IMP-2024-001",
                "title": "Automated Compliance Monitoring",
                "description": "Implement automated monitoring for ISO 27001 compliance requirements",
                "category": ImprovementCategory.COMPLIANCE_AUTOMATION,
                "phase": ImprovementPhase.DO,
                "status": ImprovementStatus.IMPLEMENTING,
                "priority": "high",
                "owner": "Compliance Team",
                "stakeholders": ["IT Security", "Compliance Officer", "Audit Team"],
                "objectives": ["Reduce manual compliance checking by 70%", "Improve compliance accuracy", "Enable real-time compliance monitoring"],
                "success_criteria": ["70% reduction in manual checks", "95% accuracy in automated checks", "Real-time alerts implemented"],
                "resources_required": {"budget": 50000, "personnel": 3, "timeline_months": 6}
            },
            {
                "initiative_id": "IMP-2024-002",
                "title": "Incident Response Process Optimization",
                "description": "Streamline incident response procedures using automation and AI",
                "category": ImprovementCategory.INCIDENT_RESPONSE,
                "phase": ImprovementPhase.CHECK,
                "status": ImprovementStatus.TESTING,
                "priority": "high",
                "owner": "SOC Team",
                "stakeholders": ["IT Operations", "Security Team", "Executive Management"],
                "objectives": ["Reduce MTTR by 40%", "Improve incident classification accuracy", "Enhance stakeholder communication"],
                "success_criteria": ["40% MTTR reduction", "90% classification accuracy", "Stakeholder satisfaction > 4.0/5.0"]
            },
            {
                "initiative_id": "IMP-2024-003",
                "title": "Risk Assessment Training Program",
                "description": "Develop comprehensive training program for risk assessors",
                "category": ImprovementCategory.TRAINING_DEVELOPMENT,
                "phase": ImprovementPhase.PLAN,
                "status": ImprovementStatus.PLANNED,
                "priority": "medium",
                "owner": "Training Department",
                "stakeholders": ["Risk Management", "HR", "Department Heads"],
                "objectives": ["Improve risk assessment quality", "Standardize assessment methodology", "Increase assessor confidence"]
            }
        ]

        for init_data in sample_initiatives:
            initiative = ImprovementInitiative(
                initiative_id=init_data["initiative_id"],
                title=init_data["title"],
                description=init_data["description"],
                category=init_data["category"],
                phase=init_data["phase"],
                status=init_data["status"],
                priority=init_data["priority"],
                created_date=datetime.now(timezone.utc) - timedelta(days=30),
                owner=init_data["owner"],
                stakeholders=init_data.get("stakeholders", []),
                objectives=init_data.get("objectives", []),
                success_criteria=init_data.get("success_criteria", []),
                resources_required=init_data.get("resources_required", {})
            )
            self.initiatives.append(initiative)

    def create_improvement_initiative(self, title: str, description: str, category: ImprovementCategory,
                                    owner: str, priority: str = "medium") -> ImprovementInitiative:
        """Create a new improvement initiative"""
        initiative_id = f"IMP-{datetime.now().strftime('%Y')}-{len(self.initiatives) + 1:03d}"

        initiative = ImprovementInitiative(
            initiative_id=initiative_id,
            title=title,
            description=description,
            category=category,
            phase=ImprovementPhase.PLAN,
            status=ImprovementStatus.IDENTIFIED,
            priority=priority,
            created_date=datetime.now(timezone.utc),
            owner=owner
        )

        self.initiatives.append(initiative)
        return initiative

    def add_to_backlog(self, title: str, description: str, category: ImprovementCategory,
                      estimated_effort: str, potential_impact: str, source: str):
        """Add an improvement idea to the backlog"""
        backlog_item = {
            "id": f"BL-{len(self.improvement_backlog) + 1:03d}",
            "title": title,
            "description": description,
            "category": category.value,
            "estimated_effort": estimated_effort,
            "potential_impact": potential_impact,
            "source": source,
            "date_added": datetime.now(timezone.utc),
            "status": "backlog"
        }
        self.improvement_backlog.append(backlog_item)

    def get_program_dashboard_data(self) -> Dict[str, Any]:
        """Get comprehensive dashboard data for the improvement program"""
        # Calculate program metrics
        total_initiatives = len(self.initiatives)
        completed_initiatives = len([i for i in self.initiatives if i.status == ImprovementStatus.COMPLETED])
        active_initiatives = len([i for i in self.initiatives if i.status in [ImprovementStatus.IMPLEMENTING, ImprovementStatus.TESTING]])

        # Calculate average progress
        avg_progress = sum(i.calculate_progress_percentage() for i in self.initiatives) / total_initiatives if total_initiatives > 0 else 0

        # Group by category
        category_stats = {}
        for category in ImprovementCategory:
            category_initiatives = [i for i in self.initiatives if i.category == category]
            category_stats[category.value] = {
                "total": len(category_initiatives),
                "completed": len([i for i in category_initiatives if i.status == ImprovementStatus.COMPLETED]),
                "active": len([i for i in category_initiatives if i.status in [ImprovementStatus.IMPLEMENTING, ImprovementStatus.TESTING]]),
                "average_progress": sum(i.calculate_progress_percentage() for i in category_initiatives) / len(category_initiatives) if category_initiatives else 0
            }

        # Phase distribution
        phase_distribution = {}
        for phase in ImprovementPhase:
            phase_distribution[phase.value] = len([i for i in self.initiatives if i.phase == phase])

        # Priority distribution
        priority_distribution = {
            "high": len([i for i in self.initiatives if i.priority == "high"]),
            "medium": len([i for i in self.initiatives if i.priority == "medium"]),
            "low": len([i for i in self.initiatives if i.priority == "low"])
        }

        # Recent activities (mock data)
        recent_activities = [
            {
                "date": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
                "activity": "Completed testing phase for Automated Compliance Monitoring",
                "type": "phase_completion"
            },
            {
                "date": (datetime.now(timezone.utc) - timedelta(days=3)).isoformat(),
                "activity": "Added new initiative: AI-Powered Risk Assessment",
                "type": "initiative_created"
            },
            {
                "date": (datetime.now(timezone.utc) - timedelta(days=5)).isoformat(),
                "activity": "Updated progress on Incident Response Optimization",
                "type": "progress_update"
            }
        ]

        return {
            "program_metrics": {
                "total_initiatives": total_initiatives,
                "completed_initiatives": completed_initiatives,
                "active_initiatives": active_initiatives,
                "completion_rate": (completed_initiatives / total_initiatives * 100) if total_initiatives > 0 else 0,
                "average_progress": avg_progress
            },
            "category_stats": category_stats,
            "phase_distribution": phase_distribution,
            "priority_distribution": priority_distribution,
            "recent_activities": recent_activities,
            "backlog_items": len(self.improvement_backlog),
            "initiatives": [i.to_dict() for i in self.initiatives]
        }

    def get_improvement_roadmap(self) -> Dict[str, Any]:
        """Generate improvement roadmap with timelines and dependencies"""
        # Group initiatives by quarter
        roadmap = {
            "Q1_2024": [],
            "Q2_2024": [],
            "Q3_2024": [],
            "Q4_2024": [],
            "Q1_2025": []
        }

        for initiative in self.initiatives:
            # Assign to quarters based on status and timeline (simplified)
            if initiative.status == ImprovementStatus.COMPLETED:
                quarter = "Q1_2024"  # Past
            elif initiative.status in [ImprovementStatus.IMPLEMENTING, ImprovementStatus.TESTING]:
                quarter = "Q2_2024"  # Current
            elif initiative.status == ImprovementStatus.PLANNED:
                quarter = "Q3_2024"  # Next
            else:
                quarter = "Q4_2024"  # Future

            roadmap[quarter].append({
                "id": initiative.initiative_id,
                "title": initiative.title,
                "category": initiative.category.value,
                "status": initiative.status.value,
                "progress": initiative.calculate_progress_percentage()
            })

        return roadmap

    def calculate_program_roi(self) -> Dict[str, Any]:
        """Calculate overall ROI for the improvement program"""
        total_investment = sum(
            initiative.resources_required.get("budget", 0)
            for initiative in self.initiatives
            if initiative.resources_required
        )

        # Mock benefits calculation (in real implementation, this would be based on actual measurements)
        benefits_realized = {
            "cost_savings": 150000,  # Annual cost savings
            "efficiency_gains": 200000,  # Value of time saved
            "risk_reduction": 50000,  # Value of reduced risk exposure
            "compliance_improvements": 75000  # Value of better compliance
        }

        total_benefits = sum(benefits_realized.values())
        roi_percentage = ((total_benefits - total_investment) / total_investment * 100) if total_investment > 0 else 0

        return {
            "total_investment": total_investment,
            "total_benefits": total_benefits,
            "net_benefits": total_benefits - total_investment,
            "roi_percentage": roi_percentage,
            "benefits_breakdown": benefits_realized,
            "payback_period_months": total_investment / (total_benefits / 12) if total_benefits > 0 else 0
        }

    def generate_lessons_learned_report(self) -> Dict[str, Any]:
        """Generate comprehensive lessons learned report"""
        completed_initiatives = [i for i in self.initiatives if i.status == ImprovementStatus.COMPLETED]

        lessons_by_category = {}
        success_patterns = []
        challenges_encountered = []
        best_practices = []

        for initiative in completed_initiatives:
            category = initiative.category.value
            if category not in lessons_by_category:
                lessons_by_category[category] = []

            lessons_by_category[category].extend(initiative.lessons_learned or [])

            # Extract patterns from successful initiatives
            if initiative.calculate_progress_percentage() > 80:
                success_patterns.append(f"Success in {initiative.title}: {', '.join(initiative.lessons_learned or ['Well executed'])}")

        return {
            "total_completed_initiatives": len(completed_initiatives),
            "lessons_by_category": lessons_by_category,
            "success_patterns": success_patterns,
            "challenges_encountered": challenges_encountered,
            "best_practices": best_practices,
            "recommendations": [
                "Focus on quick wins to build momentum",
                "Ensure stakeholder engagement throughout the process",
                "Measure impact regularly to demonstrate value",
                "Document lessons learned for future initiatives"
            ]
        }

    def get_continuous_improvement_metrics(self) -> Dict[str, Any]:
        """Get metrics specifically for continuous improvement tracking"""
        return {
            "improvement_velocity": len([i for i in self.initiatives if i.status == ImprovementStatus.COMPLETED]) / 12,  # Per month
            "backlog_size": len(self.improvement_backlog),
            "average_cycle_time": 4.5,  # Months (mock data)
            "stakeholder_satisfaction": 4.2,  # Out of 5 (mock data)
            "process_maturity_score": 78.5,  # Out of 100 (mock data)
            "innovation_index": 72.3  # Out of 100 (mock data)
        }


# Global instance
continuous_improvement_program = ContinuousImprovementProgram()


def get_continuous_improvement_dashboard_data() -> Dict[str, Any]:
    """Get continuous improvement dashboard data"""
    return continuous_improvement_program.get_program_dashboard_data()


def get_improvement_roadmap_data() -> Dict[str, Any]:
    """Get improvement roadmap data"""
    return continuous_improvement_program.get_improvement_roadmap()


def get_continuous_improvement_metrics_data() -> Dict[str, Any]:
    """Get continuous improvement metrics"""
    return continuous_improvement_program.get_continuous_improvement_metrics()


if __name__ == "__main__":
    # Demonstration of continuous improvement program
    print("Continuous Improvement Program Demonstration")
    print("=" * 50)

    # Get dashboard data
    dashboard_data = continuous_improvement_program.get_program_dashboard_data()

    print(f"Program Metrics:")
    print(f"Total Initiatives: {dashboard_data['program_metrics']['total_initiatives']}")
    print(f"Completed: {dashboard_data['program_metrics']['completed_initiatives']}")
    print(f"Active: {dashboard_data['program_metrics']['active_initiatives']}")
    print(f"Completion Rate: {dashboard_data['program_metrics']['completion_rate']:.1f}%")
    print(f"Average Progress: {dashboard_data['program_metrics']['average_progress']:.1f}%")
    # Get roadmap
    roadmap = continuous_improvement_program.get_improvement_roadmap()
    print(f"\nRoadmap for Q2 2024: {len(roadmap['Q2_2024'])} initiatives")

    # Calculate ROI
    roi = continuous_improvement_program.calculate_program_roi()
    print(f"Investment: ${roi['total_investment']:,.0f}")
    print(f"Benefits: ${roi['total_benefits']:,.0f}")
    print(f"ROI: {roi['roi_percentage']:.1f}%")
    print(f"Payback Period: {roi['payback_period_months']:.1f} months")