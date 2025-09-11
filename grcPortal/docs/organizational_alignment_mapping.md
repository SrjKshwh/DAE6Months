# Organizational Alignment Framework Mapping

## Overview
This document provides a visual framework mapping showing how the Risk Management Framework (RMF) aligns with organizational structure, governance processes, and compliance requirements for the GRC Portal.

## Organizational Structure Alignment

### Governance Hierarchy Mapping

```
┌─────────────────────────────────────────────────────────────────┐
│                    EXECUTIVE LEADERSHIP                         │
│                    (Board of Directors)                         │
├─────────────────────────────────────────────────────────────────┤
│                    CHIEF RISK OFFICER (CRO)                     │
│              Risk Strategy & Enterprise Oversight              │
├─────────────────────────────────────────────────────────────────┤
│         ┌──────────────┬──────────────┬──────────────┐         │
│         │   RISK       │  COMPLIANCE  │   AUDIT      │         │
│         │ MANAGEMENT   │   OFFICER    │   COMMITTEE  │         │
│         │   TEAM       │   (DPO)      │              │         │
├─────────┼──────────────┼──────────────┼──────────────┼─────────┤
│ BUSINESS│   ┌──────────┼──────────────┼──────────────┤ BUSINESS│
│ UNITS   │   │          │              │              │ UNITS   │
│         │   │          │              │              │         │
│ ┌───────┼───┼──┐   ┌───┼──────────────┼──────────────┼───────┐ │
│ │DEPT A │ B │ C│   │DEPT D           │              │DEPT E │ │
│ │       │ U │ U│   │                  │              │       │ │
│ │RISK   │ S │ S│   │RISK OWNERS      │              │RISK   │ │
│ │OWNERS │   │   │   │                 │              │OWNERS │ │
│ └───────┼───┼──┘   └──────────────────┼──────────────┼───────┘ │
│         │   │                         │              │         │
├─────────┴───┴─────────────────────────┴──────────────┴─────────┤
│                    OPERATIONAL TEAMS                            │
│              (IT, Security, Legal, HR, Finance)                │
└─────────────────────────────────────────────────────────────────┘
```

### Risk Management Process Flow

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   IDENTIFY      │ -> │    ASSESS       │ -> │    TREAT        │
│   Risks         │    │   Risks         │    │   Risks         │
│                 │    │                 │    │                 │
│ • Asset Inventory│    │ • Likelihood    │    │ • Accept       │
│ • Threat Analysis│    │ • Impact        │    │ • Mitigate     │
│ • Vulnerability │    │ • Risk Score    │    │ • Transfer     │
│   Assessment    │    │ • Prioritize    │    │ • Avoid        │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         v                       v                       v
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   MONITOR       │    │   REPORT        │    │   REVIEW        │
│   Controls      │    │   Status        │    │   Effectiveness │
│                 │    │                 │    │                 │
│ • Control       │    │ • Risk Register │    │ • Key Metrics   │
│   Effectiveness │    │ • Compliance    │    │ • Lessons       │
│ • KPI Tracking  │    │   Status        │    │   Learned       │
│ • Incident      │    │ • Executive     │    │ • Process       │
│   Response      │    │   Dashboard     │    │   Improvements  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## NIST RMF Phase Alignment

### RMF Process Integration Map

```
NIST RMF Integration with Organizational Processes
═══════════════════════════════════════════════════

┌─────────────────────────────────────────────────┐
│               PREPARE                           │
│  • Establish risk management strategy          │
│  • Assign roles and responsibilities           │
│  • Define risk tolerance thresholds            │
├─────────────────────────────────────────────────┤
│               CATEGORIZE                        │
│  • System characterization                     │
│  • Information categorization                  │
│  • Security objective assignment               │
├─────────────────────────────────────────────────┤
│               SELECT                           │
│  • Control selection                          │
│  • Control tailoring                          │
│  • Control supplementation                    │
├─────────────────────────────────────────────────┤
│               IMPLEMENT                        │
│  • Control implementation                     │
│  • Control documentation                      │
│  • Security policy integration                │
├─────────────────────────────────────────────────┤
│               ASSESS                           │
│  • Control effectiveness assessment           │
│  • Security control testing                   │
│  • Assessment result documentation            │
├─────────────────────────────────────────────────┤
│               AUTHORIZE                        │
│  • Risk determination                         │
│  • Authorization decision                     │
│  • Authorization package assembly             │
├─────────────────────────────────────────────────┤
│               MONITOR                          │
│  • Continuous monitoring                      │
│  • Control reassessment                       │
│  • Authorization maintenance                  │
└─────────────────────────────────────────────────┘

Organizational Alignment Points:
• Executive Leadership ↔ Prepare & Authorize
• Risk Management Team ↔ Assess & Monitor
• Business Units ↔ Categorize & Select
• IT/Security Teams ↔ Implement
• Audit Committee ↔ Assess & Monitor
```

## Compliance Framework Integration

### Multi-Framework Alignment Matrix

```
Compliance Framework Integration
═════════════════════════════════

┌─────────────────┬─────────────────┬─────────────────┬─────────────────┐
│   FRAMEWORK     │   NIST RMF      │   ISO 31000     │   GDPR          │
├─────────────────┼─────────────────┼─────────────────┼─────────────────┤
│ Risk Assessment │ Assess Phase    │ Risk           │ DPIA, Art 35    │
│                 │ RA-1, RA-2      │ Identification  │                 │
├─────────────────┼─────────────────┼─────────────────┼─────────────────┤
│ Control Design  │ Select Phase    │ Risk Treatment  │ Art 24,25       │
│                 │ SA-1 through    │ Options         │ Data Protection │
│                 │ SA-11           │                 │ by Design       │
├─────────────────┼─────────────────┼─────────────────┼─────────────────┤
│ Implementation  │ Implement Phase │ Implementation  │ Art 28,32       │
│                 │ SI-1 through    │ of Treatment    │ Security of     │
│                 │ SI-16           │                 │ Processing      │
├─────────────────┼─────────────────┼─────────────────┼─────────────────┤
│ Monitoring      │ Monitor Phase   │ Monitoring &    │ Art 24,32       │
│                 │ CA-1 through    │ Review          │ Accountability   │
│                 │ CA-7            │                 │                 │
├─────────────────┼─────────────────┼─────────────────┼─────────────────┤
│ Audit & Review  │ Assess Phase    │ Communication   │ Art 30,39       │
│                 │ CA-1 through    │ & Consultation  │ Records of      │
│                 │ CA-7            │                 │ Processing      │
└─────────────────┴─────────────────┴─────────────────┴─────────────────┘
```

## Role-Based Access Control (RBAC) Mapping

### Governance Role Permissions Matrix

```
Role-Based Permissions and Responsibilities
════════════════════════════════════════════

┌─────────────────┬─────────┬─────────┬─────────┬─────────┬─────────┐
│ FUNCTION        │  USER   │ AUDITOR │ RISK    │ COMPL   │  ADMIN  │
│                 │         │         │ OWNER   │ OFFICER │         │
├─────────────────┼─────────┼─────────┼─────────┼─────────┼─────────┤
│ View Own Risks  │    ✓    │    ✓    │    ✓    │    ✓    │    ✓    │
├─────────────────┼─────────┼─────────┼─────────┼─────────┼─────────┤
│ View All Risks  │         │    ✓    │    ✓    │    ✓    │    ✓    │
├─────────────────┼─────────┼─────────┼─────────┼─────────┼─────────┤
│ Create Risks    │    ✓    │    ✓    │    ✓    │    ✓    │    ✓    │
├─────────────────┼─────────┼─────────┼─────────┼─────────┼─────────┤
│ Edit Risks      │         │         │    ✓    │    ✓    │    ✓    │
├─────────────────┼─────────┼─────────┼─────────┼─────────┼─────────┤
│ Approve Risks   │         │         │    ✓    │         │    ✓    │
├─────────────────┼─────────┼─────────┼─────────┼─────────┼─────────┤
│ Delete Risks    │         │         │         │         │    ✓    │
├─────────────────┼─────────┼─────────┼─────────┼─────────┼─────────┤
│ View Compliance │    ✓    │    ✓    │    ✓    │    ✓    │    ✓    │
├─────────────────┼─────────┼─────────┼─────────┼─────────┼─────────┤
│ Edit Compliance │         │         │         │    ✓    │    ✓    │
├─────────────────┼─────────┼─────────┼─────────┼─────────┼─────────┤
│ View Audit Logs │         │    ✓    │         │    ✓    │    ✓    │
├─────────────────┼─────────┼─────────┼─────────┼─────────┼─────────┤
│ User Management │         │         │         │         │    ✓    │
├─────────────────┼─────────┼─────────┼─────────┼─────────┼─────────┤
│ System Config   │         │         │         │         │    ✓    │
├─────────────────┼─────────┼─────────┼─────────┼─────────┼─────────┤
│ Escalation      │         │    ✓    │    ✓    │    ✓    │    ✓    │
│ Override        │         │         │         │         │         │
└─────────────────┴─────────┴─────────┴─────────┴─────────┴─────────┘

Legend:
✓ = Permitted
□ = Not Permitted
```

## Decision-Making Authority Flow

### Risk Approval Workflow

```
Risk Approval and Escalation Workflow
═══════════════════════════════════════

┌─────────────────────────────────────────────────────────────┐
│                    RISK IDENTIFIED                          │
│                    (Any User)                               │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      v
┌─────────────────────────────────────────────────────────────┐
│                INITIAL ASSESSMENT                          │
│                (Risk Owner/Auditor)                        │
│                                                             │
│ Risk Score Calculation:                                    │
│ • Likelihood (1-5) × Impact (1-5) = Score (1-25)           │
│ • Score 1-5: Low → Auto-approve                            │
│ • Score 6-12: Medium → Department approval                 │
│ • Score 13-20: High → Senior management approval           │
│ • Score 21-25: Critical → Executive approval               │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      v
┌─────────────────────────────────────────────────────────────┐
│              APPROVAL ROUTING                               │
│                                                             │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ LEVEL 1: Business Unit (Score 1-5)                      │ │
│ │ • Risk Owner approval                                   │ │
│ │ • Automatic notification to stakeholders                │ │
│ └─────────────────────────────────────────────────────────┘ │
│                                                             │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ LEVEL 2: Department (Score 6-12)                        │ │
│ │ • Department head approval                              │ │
│ │ • Risk assessment review                                 │ │
│ │ • Mitigation plan review                                 │ │
│ └─────────────────────────────────────────────────────────┘ │
│                                                             │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ LEVEL 3: Senior Management (Score 13-20)                │ │
│ │ • Senior management approval                            │ │
│ │ • Board notification                                     │ │
│ │ • Executive risk committee review                       │ │
│ └─────────────────────────────────────────────────────────┘ │
│                                                             │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ LEVEL 4: Executive (Score 21-25)                        │ │
│ │ • Board of Directors approval                           │ │
│ │ • External auditor notification                         │ │
│ │ • Regulatory authority notification (if required)       │ │
│ └─────────────────────────────────────────────────────────┘ │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      v
┌─────────────────────────────────────────────────────────────┐
│                IMPLEMENTATION                               │
│                (Assigned Teams)                             │
│                                                             │
│ • Mitigation plan execution                                 │
│ • Control implementation                                    │
│ • Progress monitoring                                       │
│ • Effectiveness validation                                  │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      v
┌─────────────────────────────────────────────────────────────┐
│                 MONITORING & REVIEW                         │
│                 (Continuous Process)                        │
│                                                             │
│ • KPI tracking                                              │
│ • Control effectiveness assessment                          │
│ • Risk reassessment                                         │
│ • Annual review cycle                                       │
└─────────────────────────────────────────────────────────────┘
```

## Communication and Reporting Structure

### Information Flow Diagram

```
Information Flow and Communication Channels
═════════════════════════════════════════════

┌─────────────────────────────────────────────────────────────┐
│                 EXECUTIVE DASHBOARD                         │
│  • Risk heat maps                                           │
│  • Compliance status                                        │
│  • Key risk indicators                                      │
│  • Executive summaries                                      │
├─────────────────────────────────────────────────────────────┤
│                 MANAGEMENT REPORTING                        │
│  • Department risk reports                                  │
│  • Mitigation progress                                      │
│  • Compliance dashboards                                    │
│  • Escalation alerts                                        │
├─────────────────────────────────────────────────────────────┤
│                 OPERATIONAL COMMUNICATION                   │
│  • Risk register updates                                    │
│  • Control implementation status                            │
│  • Incident reports                                         │
│  • Training notifications                                   │
├─────────────────────────────────────────────────────────────┤
│                 AUDIT & COMPLIANCE                          │
│  • Audit findings                                           │
│  • Compliance violations                                    │
│  • Remediation tracking                                     │
│  • Regulatory reporting                                     │
└─────────────────────────────────────────────────────────────┘

Communication Frequency:
• Daily: Critical risk alerts
• Weekly: Risk register updates
• Monthly: Compliance status reports
• Quarterly: Executive risk reviews
• Annually: Comprehensive risk assessments
```

## Technology Integration Points

### System Architecture Alignment

```
Technology Stack Integration
═════════════════════════════

┌─────────────────────────────────────────────────────────────┐
│                    USER INTERFACE                           │
│  • Web Dashboard (Flask/Jinja2)                            │
│  • Risk Assessment Forms                                   │
│  • Compliance Reporting                                    │
│  • Executive Dashboards                                     │
├─────────────────────────────────────────────────────────────┤
│                    APPLICATION LAYER                        │
│  • Risk Calculation Engine                                 │
│  • Approval Workflow Engine                                │
│  • Compliance Monitoring                                   │
│  • Audit Trail Generation                                  │
├─────────────────────────────────────────────────────────────┤
│                    DATA LAYER                               │
│  • Risk Database (SQLAlchemy)                              │
│  • Audit Logs                                              │
│  • Compliance Records                                      │
│  • User Management                                         │
├─────────────────────────────────────────────────────────────┤
│                    INTEGRATION LAYER                        │
│  • API Endpoints                                           │
│  • External System Connectors                              │
│  • Notification Services                                   │
│  • Reporting Engines                                       │
└─────────────────────────────────────────────────────────────┘

Key Integration Points:
• SSO Integration for user authentication
• SIEM integration for security monitoring
• ERP integration for business process data
• Email/SMS for notifications and alerts
• Document management for evidence storage
```

## Success Metrics Dashboard

### KPI Framework Mapping

```
Key Performance Indicators (KPIs)
═══════════════════════════════════

┌─────────────────────────────────────────────────────────────┐
│                 RISK MANAGEMENT KPIs                       │
├─────────────────────────────────────────────────────────────┤
│ • Risk Assessment Completion Rate (>95%)                   │
│ • Average Risk Resolution Time (<30 days)                  │
│ • Risk Register Accuracy (>90%)                            │
│ • Critical Risk Mitigation Rate (>98%)                     │
├─────────────────────────────────────────────────────────────┤
│                 COMPLIANCE KPIs                            │
├─────────────────────────────────────────────────────────────┤
│ • Compliance Score (>95%)                                  │
│ • Audit Finding Reduction (>80%)                           │
│ • Regulatory Reporting Timeliness (100%)                   │
│ • Training Completion Rate (>90%)                          │
├─────────────────────────────────────────────────────────────┤
│                 GOVERNANCE KPIs                            │
├─────────────────────────────────────────────────────────────┤
│ • Process Adherence Rate (>95%)                            │
│ • Escalation Effectiveness (>90%)                          │
│ • Stakeholder Satisfaction (>85%)                          │
│ • Continuous Improvement Initiatives (>4/year)             │
└─────────────────────────────────────────────────────────────┘

Dashboard Views by Role:
• Executive: High-level KPIs and trends
• Management: Department-specific metrics
• Operational: Task-level performance
• Audit: Compliance and control metrics
```

---

*This organizational alignment mapping provides a comprehensive visual framework for understanding how risk management processes integrate with organizational structure, governance, and compliance requirements.*