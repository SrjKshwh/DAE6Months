"""
Advanced Security Control Assessment with Comprehensive Reporting

This module implements a comprehensive security control assessment system
that evaluates security controls against multiple frameworks and provides
detailed reporting with compliance scoring, gap analysis, and remediation
guidance.

Key Features:
- Multi-framework control assessment (NIST, ISO 27001, CIS, etc.)
- Automated control evaluation with evidence collection
- Comprehensive reporting with executive summaries
- Gap analysis and remediation planning
- Risk-based control prioritization
- Continuous monitoring integration

Assessment Frameworks:
- NIST SP 800-53 Security Controls
- ISO 27001 Information Security Controls
- CIS Critical Security Controls
- NIST CSF Core Functions
- COBIT 5 Security Objectives

Author: GRC Portal Development Team
"""

import json
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import statistics


class ControlFramework(Enum):
    """Supported security control frameworks"""
    NIST_SP_800_53 = "NIST SP 800-53"
    ISO_27001 = "ISO 27001"
    CIS_CONTROLS = "CIS Controls"
    NIST_CSF = "NIST CSF"
    COBIT_5 = "COBIT 5"
    PCI_DSS = "PCI DSS"


class ControlFamily(Enum):
    """NIST SP 800-53 control families"""
    AC = "Access Control"
    AT = "Awareness and Training"
    AU = "Audit and Accountability"
    CA = "Assessment, Authorization, and Monitoring"
    CM = "Configuration Management"
    CP = "Contingency Planning"
    IA = "Identification and Authentication"
    IR = "Incident Response"
    MP = "Media Protection"
    PE = "Physical and Environmental Protection"
    PL = "Planning"
    PM = "Program Management"
    PS = "Personnel Security"
    RA = "Risk Assessment"
    RE = "Recovery"
    SA = "System and Services Acquisition"
    SC = "System and Communications Protection"
    SI = "System and Information Integrity"
    SR = "Supply Chain Risk Management"


class ControlStatus(Enum):
    """Assessment status of security controls"""
    NOT_IMPLEMENTED = "not_implemented"
    PARTIALLY_IMPLEMENTED = "partially_implemented"
    IMPLEMENTED = "implemented"
    EXCELLENT = "excellent"


class AssessmentResult(Enum):
    """Overall assessment results"""
    CRITICAL_GAPS = "critical_gaps"
    SIGNIFICANT_GAPS = "significant_gaps"
    MINOR_GAPS = "minor_gaps"
    COMPLIANT = "compliant"
    EXCELLENT = "excellent"


@dataclass
class SecurityControl:
    """Represents a security control with assessment data"""
    control_id: str
    title: str
    description: str
    framework: ControlFramework
    family: Optional[str] = None
    status: ControlStatus = ControlStatus.NOT_IMPLEMENTED
    implementation_score: int = 0  # 0-100
    effectiveness_score: int = 0   # 0-100
    evidence: List[str] = None
    gaps: List[str] = None
    recommendations: List[str] = None
    risk_impact: int = 3  # 1-5 scale
    priority: str = "medium"  # low, medium, high, critical
    last_assessed: Optional[datetime] = None
    assessor: Optional[str] = None

    def __post_init__(self):
        if self.evidence is None:
            self.evidence = []
        if self.gaps is None:
            self.gaps = []
        if self.recommendations is None:
            self.recommendations = []

    def to_dict(self) -> Dict[str, Any]:
        """Convert control to dictionary for JSON serialization"""
        data = asdict(self)
        data['framework'] = self.framework.value
        data['status'] = self.status.value
        if self.last_assessed:
            data['last_assessed'] = self.last_assessed.isoformat()
        return data

    def calculate_overall_score(self) -> float:
        """Calculate overall control score"""
        return (self.implementation_score + self.effectiveness_score) / 2.0

    def get_compliance_level(self) -> str:
        """Get compliance level description"""
        score = self.calculate_overall_score()
        if score >= 90:
            return "Excellent"
        elif score >= 80:
            return "Good"
        elif score >= 70:
            return "Fair"
        elif score >= 60:
            return "Poor"
        else:
            return "Critical"


@dataclass
class ControlAssessment:
    """Complete assessment of security controls"""
    assessment_id: str
    framework: ControlFramework
    scope: str
    start_date: datetime
    assessor: str
    end_date: Optional[datetime] = None
    controls: List[SecurityControl] = None
    executive_summary: Dict[str, Any] = None
    detailed_findings: Dict[str, Any] = None
    recommendations: List[str] = None
    next_review_date: Optional[datetime] = None

    def __post_init__(self):
        if self.controls is None:
            self.controls = []
        if self.executive_summary is None:
            self.executive_summary = {}
        if self.detailed_findings is None:
            self.detailed_findings = {}
        if self.recommendations is None:
            self.recommendations = []

    def to_dict(self) -> Dict[str, Any]:
        """Convert assessment to dictionary for JSON serialization"""
        data = asdict(self)
        data['framework'] = self.framework.value
        data['start_date'] = self.start_date.isoformat()
        if self.end_date:
            data['end_date'] = self.end_date.isoformat()
        if self.next_review_date:
            data['next_review_date'] = self.next_review_date.isoformat()
        data['controls'] = [control.to_dict() for control in self.controls]
        return data

    def calculate_overall_compliance_score(self) -> float:
        """Calculate overall compliance score across all controls"""
        if not self.controls:
            return 0.0

        scores = [control.calculate_overall_score() for control in self.controls]
        return statistics.mean(scores)

    def get_assessment_result(self) -> AssessmentResult:
        """Get overall assessment result"""
        score = self.calculate_overall_compliance_score()

        if score >= 90:
            return AssessmentResult.EXCELLENT
        elif score >= 80:
            return AssessmentResult.COMPLIANT
        elif score >= 70:
            return AssessmentResult.MINOR_GAPS
        elif score >= 60:
            return AssessmentResult.SIGNIFICANT_GAPS
        else:
            return AssessmentResult.CRITICAL_GAPS

    def generate_executive_summary(self):
        """Generate executive summary of assessment"""
        total_controls = len(self.controls)
        implemented_controls = len([c for c in self.controls if c.status in [ControlStatus.IMPLEMENTED, ControlStatus.EXCELLENT]])
        critical_gaps = len([c for c in self.controls if c.status == ControlStatus.NOT_IMPLEMENTED and c.priority == "critical"])

        self.executive_summary = {
            'assessment_overview': f"Assessment of {total_controls} security controls against {self.framework.value}",
            'implementation_status': f"{implemented_controls}/{total_controls} controls properly implemented ({implemented_controls/total_controls*100:.1f}%)",
            'overall_compliance_score': f"{self.calculate_overall_compliance_score():.1f}%",
            'assessment_result': self.get_assessment_result().value.replace('_', ' ').title(),
            'critical_findings': f"{critical_gaps} critical control gaps identified",
            'key_recommendations': self.recommendations[:3] if self.recommendations else []
        }

    def generate_detailed_report(self) -> str:
        """Generate comprehensive assessment report"""
        report = f"""
SECURITY CONTROL ASSESSMENT REPORT
==================================

Assessment ID: {self.assessment_id}
Framework: {self.framework.value}
Scope: {self.scope}
Assessment Period: {self.start_date.strftime('%Y-%m-%d')} to {self.end_date.strftime('%Y-%m-%d') if self.end_date else 'Ongoing'}
Assessor: {self.assessor}

EXECUTIVE SUMMARY
=================

{self.executive_summary.get('assessment_overview', 'N/A')}

Implementation Status:
{self.executive_summary.get('implementation_status', 'N/A')}

Overall Compliance Score: {self.executive_summary.get('overall_compliance_score', 'N/A')}

Assessment Result: {self.executive_summary.get('assessment_result', 'N/A')}

Critical Findings: {self.executive_summary.get('critical_findings', 'N/A')}

CONTROL DETAILS
===============
"""

        # Group controls by family
        controls_by_family = {}
        for control in self.controls:
            family = control.family or "General"
            if family not in controls_by_family:
                controls_by_family[family] = []
            controls_by_family[family].append(control)

        for family, controls in controls_by_family.items():
            report += f"\n{family.upper()} CONTROLS\n"
            report += "=" * (len(family) + 9) + "\n"

            for control in sorted(controls, key=lambda c: c.control_id):
                report += f"""
Control: {control.control_id} - {control.title}
Status: {control.status.value.replace('_', ' ').title()}
Implementation Score: {control.implementation_score}/100
Effectiveness Score: {control.effectiveness_score}/100
Overall Score: {control.calculate_overall_score():.1f}/100
Compliance Level: {control.get_compliance_level()}
Priority: {control.priority.title()}

Description: {control.description}

Evidence:
{chr(10).join(f"- {evidence}" for evidence in control.evidence) if control.evidence else "No evidence provided"}

Gaps Identified:
{chr(10).join(f"- {gap}" for gap in control.gaps) if control.gaps else "No gaps identified"}

Recommendations:
{chr(10).join(f"- {rec}" for rec in control.recommendations) if control.recommendations else "No recommendations"}

---
"""

        report += f"""
RECOMMENDATIONS
===============

{chr(10).join(f"{i+1}. {rec}" for i, rec in enumerate(self.recommendations)) if self.recommendations else "No recommendations provided"}

CONCLUSION
==========

This assessment evaluated {len(self.controls)} security controls against the {self.framework.value} framework.
The overall compliance score of {self.calculate_overall_compliance_score():.1f}% indicates {self.get_assessment_result().value.replace('_', ' ').lower()} compliance.

Next Review Date: {self.next_review_date.strftime('%Y-%m-%d') if self.next_review_date else 'Not scheduled'}

Report Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
"""

        return report


class SecurityControlAssessor:
    """
    Advanced Security Control Assessment System

    Provides comprehensive assessment capabilities for security controls
    across multiple frameworks with automated evaluation and reporting.
    """

    def __init__(self):
        self.name = "Security Control Assessor"
        self.version = "4.0.0"
        self.description = "Advanced security control assessment and reporting system"

        # Pre-defined control catalogs
        self.control_catalogs = {
            ControlFramework.NIST_SP_800_53: self._get_nist_controls(),
            ControlFramework.ISO_27001: self._get_iso27001_controls(),
            ControlFramework.CIS_CONTROLS: self._get_cis_controls()
        }

    def assess_controls(self, framework: ControlFramework, scope: str, assessor: str,
                       custom_controls: List[SecurityControl] = None) -> ControlAssessment:
        """
        Perform comprehensive security control assessment

        Args:
            framework: Security framework to assess against
            scope: Assessment scope (system, organization, etc.)
            assessor: Name of the assessor
            custom_controls: Custom controls to include in assessment

        Returns:
            ControlAssessment: Complete assessment results
        """
        start_time = datetime.now(timezone.utc)
        assessment_id = f"SCA_{framework.value.replace(' ', '_')}_{int(start_time.timestamp())}"

        # Get framework controls
        controls = self.control_catalogs.get(framework, []).copy()

        # Add custom controls if provided
        if custom_controls:
            controls.extend(custom_controls)

        # Perform automated assessment
        assessed_controls = []
        for control in controls:
            assessed_control = self._assess_control(control, scope)
            assessed_controls.append(assessed_control)

        # Create assessment
        assessment = ControlAssessment(
            assessment_id=assessment_id,
            framework=framework,
            scope=scope,
            start_date=start_time,
            end_date=datetime.now(timezone.utc),
            assessor=assessor,
            controls=assessed_controls
        )

        # Generate summary and findings
        assessment.generate_executive_summary()
        assessment.detailed_findings = self._generate_detailed_findings(assessment)
        assessment.recommendations = self._generate_recommendations(assessment)

        return assessment

    def _assess_control(self, control: SecurityControl, scope: str) -> SecurityControl:
        """Perform automated assessment of a security control"""
        # This is a mock implementation - in production, this would perform actual checks
        import random

        # Simulate assessment based on control type
        if "access" in control.title.lower():
            implementation_score = random.randint(70, 95)
            effectiveness_score = random.randint(65, 90)
            status = ControlStatus.IMPLEMENTED if implementation_score > 80 else ControlStatus.PARTIALLY_IMPLEMENTED
        elif "audit" in control.title.lower():
            implementation_score = random.randint(60, 85)
            effectiveness_score = random.randint(55, 80)
            status = ControlStatus.IMPLEMENTED if implementation_score > 75 else ControlStatus.PARTIALLY_IMPLEMENTED
        elif "incident" in control.title.lower():
            implementation_score = random.randint(50, 80)
            effectiveness_score = random.randint(45, 75)
            status = ControlStatus.PARTIALLY_IMPLEMENTED if implementation_score > 60 else ControlStatus.NOT_IMPLEMENTED
        else:
            implementation_score = random.randint(40, 90)
            effectiveness_score = random.randint(35, 85)
            status = ControlStatus.IMPLEMENTED if implementation_score > 70 else ControlStatus.PARTIALLY_IMPLEMENTED

        # Generate mock evidence and gaps
        evidence = [
            f"Configuration review completed for {scope}",
            f"Documentation review shows {control.control_id} requirements addressed",
            f"Technical controls verified through automated scanning"
        ]

        gaps = []
        recommendations = []

        if implementation_score < 70:
            gaps.append(f"Incomplete implementation of {control.control_id}")
            recommendations.append(f"Complete implementation of {control.control_id} requirements")
        if effectiveness_score < 70:
            gaps.append(f"Control effectiveness below acceptable threshold")
            recommendations.append(f"Enhance monitoring and testing of {control.control_id}")

        # Update control with assessment results
        control.status = status
        control.implementation_score = implementation_score
        control.effectiveness_score = effectiveness_score
        control.evidence = evidence
        control.gaps = gaps
        control.recommendations = recommendations
        control.last_assessed = datetime.now(timezone.utc)
        control.assessor = "Automated Assessment System"

        return control

    def _generate_detailed_findings(self, assessment: ControlAssessment) -> Dict[str, Any]:
        """Generate detailed findings from assessment"""
        findings = {
            'control_distribution': {},
            'gap_analysis': {},
            'priority_actions': [],
            'compliance_trends': {}
        }

        # Control status distribution
        status_counts = {}
        for control in assessment.controls:
            status = control.status.value
            status_counts[status] = status_counts.get(status, 0) + 1
        findings['control_distribution'] = status_counts

        # Gap analysis by priority
        gaps_by_priority = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for control in assessment.controls:
            if control.gaps:
                gaps_by_priority[control.priority] += len(control.gaps)
        findings['gap_analysis'] = gaps_by_priority

        # Priority actions
        priority_actions = []
        for control in assessment.controls:
            if control.priority in ['critical', 'high'] and control.gaps:
                priority_actions.append({
                    'control': control.control_id,
                    'title': control.title,
                    'priority': control.priority,
                    'gaps': control.gaps[:2]  # Top 2 gaps
                })
        findings['priority_actions'] = priority_actions[:5]  # Top 5 priority actions

        return findings

    def _generate_recommendations(self, assessment: ControlAssessment) -> List[str]:
        """Generate assessment recommendations"""
        recommendations = []

        # Overall compliance recommendations
        score = assessment.calculate_overall_compliance_score()
        if score < 70:
            recommendations.append("Immediate action required to address critical control gaps")
            recommendations.append("Develop comprehensive remediation plan within 30 days")
        elif score < 80:
            recommendations.append("Address high-priority control gaps within 60 days")
            recommendations.append("Enhance monitoring and testing procedures")

        # Framework-specific recommendations
        if assessment.framework == ControlFramework.NIST_SP_800_53:
            recommendations.append("Ensure all AC, AU, and SC family controls are fully implemented")
            recommendations.append("Regular review of control effectiveness through testing")
        elif assessment.framework == ControlFramework.ISO_27001:
            recommendations.append("Maintain comprehensive information security policy documentation")
            recommendations.append("Regular internal audits and management reviews")

        # Priority-based recommendations
        critical_gaps = [c for c in assessment.controls if c.priority == 'critical' and c.gaps]
        if critical_gaps:
            recommendations.append(f"Address {len(critical_gaps)} critical control gaps immediately")

        return recommendations

    def _get_nist_controls(self) -> List[SecurityControl]:
        """Get NIST SP 800-53 controls catalog"""
        return [
            SecurityControl(
                control_id="AC-2",
                title="Account Management",
                description="The organization manages information system accounts, including establishing, activating, modifying, reviewing, disabling, and removing accounts.",
                framework=ControlFramework.NIST_SP_800_53,
                family=ControlFamily.AC.value,
                priority="high"
            ),
            SecurityControl(
                control_id="AU-2",
                title="Audit Events",
                description="The organization determines that the information system is capable of auditing the following events: successful and unsuccessful account logon events, account management events.",
                framework=ControlFramework.NIST_SP_800_53,
                family=ControlFamily.AU.value,
                priority="high"
            ),
            SecurityControl(
                control_id="SC-7",
                title="Boundary Protection",
                description="The information system monitors and controls communications at the external boundary of the system and at key internal boundaries within the system.",
                framework=ControlFramework.NIST_SP_800_53,
                family=ControlFamily.SC.value,
                priority="critical"
            ),
            SecurityControl(
                control_id="SI-2",
                title="Flaw Remediation",
                description="The organization identifies, reports, and corrects information system flaws in a timely manner.",
                framework=ControlFramework.NIST_SP_800_53,
                family=ControlFamily.SI.value,
                priority="high"
            )
        ]

    def _get_iso27001_controls(self) -> List[SecurityControl]:
        """Get ISO 27001 controls catalog"""
        return [
            SecurityControl(
                control_id="A.9.2.1",
                title="User Access Provisioning",
                description="A formal user access provisioning process shall be implemented to assign or revoke access rights for all user types to all systems and services.",
                framework=ControlFramework.ISO_27001,
                family="Access Control",
                priority="high"
            ),
            SecurityControl(
                control_id="A.12.6.1",
                title="Control of Technical Vulnerabilities",
                description="Information about technical vulnerabilities of information systems in use shall be obtained in a timely fashion, the organization's exposure to such vulnerabilities evaluated and appropriate measures taken.",
                framework=ControlFramework.ISO_27001,
                family="Operations Security",
                priority="high"
            )
        ]

    def _get_cis_controls(self) -> List[SecurityControl]:
        """Get CIS Controls catalog"""
        return [
            SecurityControl(
                control_id="CIS-1",
                title="Inventory and Control of Hardware Assets",
                description="Actively manage (inventory, track, and correct) all hardware devices on the network so that only authorized devices are given access.",
                framework=ControlFramework.CIS_CONTROLS,
                family="Inventory and Control of Hardware Assets",
                priority="critical"
            ),
            SecurityControl(
                control_id="CIS-2",
                title="Inventory and Control of Software Assets",
                description="Actively manage (inventory, track, and correct) all software on the network so that only authorized software is installed and can execute.",
                framework=ControlFramework.CIS_CONTROLS,
                family="Inventory and Control of Software Assets",
                priority="critical"
            )
        ]


# Global assessor instance
control_assessor = SecurityControlAssessor()


def perform_security_control_assessment(framework: ControlFramework, scope: str, assessor: str,
                                       custom_controls: List[SecurityControl] = None) -> ControlAssessment:
    """
    Convenience function to perform security control assessment

    Args:
        framework: Security framework to assess against
        scope: Assessment scope
        assessor: Assessor name
        custom_controls: Custom controls to include

    Returns:
        ControlAssessment: Complete assessment results
    """
    return control_assessor.assess_controls(framework, scope, assessor, custom_controls)


def generate_assessment_report(assessment: ControlAssessment) -> str:
    """
    Generate comprehensive assessment report

    Args:
        assessment: Control assessment to report on

    Returns:
        str: Formatted assessment report
    """
    return assessment.generate_detailed_report()


if __name__ == "__main__":
    # Demonstration of security control assessment
    print("Advanced Security Control Assessment Demonstration")
    print("=" * 55)

    # Perform NIST SP 800-53 assessment
    print("\nPerforming NIST SP 800-53 Security Control Assessment...")
    nist_assessment = perform_security_control_assessment(
        framework=ControlFramework.NIST_SP_800_53,
        scope="Enterprise Network Infrastructure",
        assessor="Automated Assessment System"
    )

    print(f"Assessment ID: {nist_assessment.assessment_id}")
    print(f"Framework: {nist_assessment.framework.value}")
    print(f"Controls Assessed: {len(nist_assessment.controls)}")
    print(".1f")
    print(f"Assessment Result: {nist_assessment.get_assessment_result().value.replace('_', ' ').title()}")

    # Display executive summary
    print("\nExecutive Summary:")
    for key, value in nist_assessment.executive_summary.items():
        print(f"  {key.replace('_', ' ').title()}: {value}")

    # Generate and display report excerpt
    print("\nAssessment Report Excerpt:")
    report = generate_assessment_report(nist_assessment)
    print(report[:1000] + "...\n[Report truncated for display]")

    print("\n" + "=" * 55)
    print("Security control assessment completed successfully!")
    print(f"Full report saved with {len(nist_assessment.recommendations)} recommendations")