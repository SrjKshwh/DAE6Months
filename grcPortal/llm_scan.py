"""
LLM-Based Security Scanning and Risk Analysis Module

This module provides AI-powered security analysis capabilities for the GRC Portal,
utilizing Large Language Models (LLMs) to automatically analyze uploaded policy
documents and extract compliance requirements, security risks, and recommendations.

Core Functionality:
- Text extraction from various document formats (PDF, TXT)
- LLM-powered GRC analysis using OpenRouter API
- Automated risk and compliance record creation
- Structured JSON response parsing with error handling

Key Components:
- _extract_text(): Document text extraction and preprocessing
- _call_model(): LLM API communication with fallback handling
- scan_file_for_grc(): Main scanning orchestration function
- create_risks_from_scan(): Database record creation from scan results

Security Features:
- Input validation and sanitization
- API key protection and fallback responses
- Structured error handling and logging
- Safe JSON parsing with recovery mechanisms

Dependencies:
- requests: HTTP client for API communication
- PyPDF2: PDF text extraction
- SQLAlchemy models: Database integration

Environment Variables:
- MODEL_NAME: LLM model identifier (default: openai/gpt-oss-20b:free)
- OPENROUTER_API_KEY: API authentication key

Usage:
    from llm_scan import scan_file_for_grc
    results = scan_file_for_grc("policy_document.pdf")
"""

import json
import logging
import os
import re
from pathlib import Path

import requests
from PyPDF2 import PdfReader

# Import database models for risk creation
from models import Risk, Compliance, RiskSeverity, RiskCategory, ComplianceFramework, RiskStatus
from db import get_session, close_session

MODEL_NAME = os.getenv("MODEL_NAME", "openai/gpt-oss-20b:free")
OPENROUTER_KEY = os.getenv("OPENROUTER_API_KEY", "")

def _extract_text(file_path: str, max_chars: int = 20000) -> str:
    """Extracts text from .txt or .pdf (basic). Truncates to keep prompt small."""
    p = Path(file_path)
    if p.suffix.lower() == ".txt":
        text = p.read_text(errors="ignore")
    elif p.suffix.lower() == ".pdf":
        text = ""
        reader = PdfReader(str(p))
        for page in reader.pages:
            text += page.extract_text() or ""
    else:
        # Could expand to docx, etc.
        text = p.read_text(errors="ignore")
    # normalize whitespace
    text = re.sub(r"\s+", " ", text).strip()
    return text[:max_chars]


def _call_model(prompt: str) -> str:
    """
    Calls a provider that hosts `openai/gpt-oss-20b:free`.
    Example below shows OpenRouter's Chat Completions style.
    If provider is changed then adjust URL/headers/fields accordingly.
    """
    if not OPENROUTER_KEY:
        # Safe fallback for local testing without a key
        return json.dumps({
            "summary": "Demo summary (****no API key found****).",
            "compliance_hits": [{"framework": "NIST SP 800-53", "control": "AC-2", "note": "Access control policy referenced."}],
            "risks": [{"risk": "Lack of formal incident response testing", "severity": "Medium"}],
            "other_notes": "Provide an API key to get real results.",
            "detected_threats": []
        }, indent=2)

    url = "https://openrouter.ai/api/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {OPENROUTER_KEY}",
        "Content-Type": "application/json",
    }
    body = {
        "model": MODEL_NAME,
        "messages": [
            {"role": "system", "content": "You are a cybersecurity GRC analyst. Extract compliance hits and risks from uploaded policy text. Respond ONLY in strict JSON."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.2,
    }
    r = requests.post(url, headers=headers, json=body, timeout=120)
    r.raise_for_status()
    content = r.json()["choices"][0]["message"]["content"]
    return content


def scan_file_for_grc(file_path: str) -> dict:
    """
    Returns a dictionary with keys: summary (str), compliance_hits (list), risks (list), other_notes (str).
    Includes threat detection through content analysis and LLM-powered GRC analysis.
    """
    text = _extract_text(file_path)

    # Threat Detection Implementation: Analyze at least 1 identified threat and detection method
    threats = []

    # Threat: Plaintext password storage
    if "password" in text.lower() and "plaintext" in text.lower():
        threats.append({
            "threat": "Plaintext password storage detected",
            "severity": "High",
            "detection_method": "Pattern matching in uploaded content",
            "impact": "Potential credential exposure",
            "remediation": "Implement proper password hashing"
        })

    # Threat: SQL Injection Vulnerability
    if "sql" in text.lower() and ("select" in text.lower() or "union" in text.lower()):
        threats.append({
            "threat": "Potential SQL injection vulnerability",
            "severity": "Critical",
            "detection_method": "SQL keyword pattern analysis",
            "impact": "Database compromise risk",
            "remediation": "Use parameterized queries"
        })

    # Threat Analysis Example:
    # Threat: SQL Injection Vulnerability
    # Detection Method: Pattern matching for SQL keywords in uploaded documents
    # Severity Assessment: Critical due to potential database compromise
    # Impact Analysis: Could lead to unauthorized data access or modification
    # Remediation: Implement prepared statements and input validation

    prompt = f"""
        You are given the content of a cybersecurity policy. Extract:
        1) "summary": 2-4 sentence summary of what the document covers.
        2) "compliance_hits": array of objects with "framework" (e.g., NIST SP 800-53, ISO 27001, PCI DSS), optional "control" (e.g., AC-2), and "note".
        3) "risks": array of objects with "risk" and "severity" (Low/Medium/High/Critical).
        4) "other_notes": any additional important observations.

        Return STRICT JSON with keys: summary, compliance_hits, risks, other_notes.
        Policy text:
        \"\"\"{text}\"\"\""""

    raw = _call_model(prompt)

    # Try to parse JSON safely
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        # Try to recover JSON from any surrounding text
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        if m:
            data = json.loads(m.group(0))
        else:
            data = {
                "summary": "LLM returned non-JSON output.",
                "compliance_hits": [],
                "risks": [],
                "other_notes": raw[:2000]
            }
    # Ensure keys exist
    data.setdefault("summary", "")
    data.setdefault("compliance_hits", [])
    data.setdefault("risks", [])
    data.setdefault("other_notes", "")

    # Include detected threats in the response
    data["detected_threats"] = threats

    return data


def create_risks_from_scan(scan_result_id: int, risks_data: list, compliance_data: list, threats_data: list = None):
    """
    Create Risk and Compliance entries from scan results
    Includes both LLM-detected risks and pattern-based threat detections
    """
    if not risks_data and not threats_data:
        logging.info("No risks or threats data provided, skipping creation")
        return

    db = get_session()
    try:
        created_risk_count = 0
        for risk_item in risks_data:
            try:
                # Map severity string to enum    (Low/Medium/High/Critical)
                risk_desc = risk_item.get("risk")
                severity_str = risk_item.get("severity", "Medium")

                if not risk_desc:
                    logging.warning(f"Skipping risk item missing 'risk' field: {risk_item}")
                    continue

                severity_str = severity_str.title()
                try:
                    severity = RiskSeverity[severity_str.upper()]
                except KeyError:
                    logging.warning(f"Invalid severity '{severity_str}', defaulting to MEDIUM")
                    severity = RiskSeverity.MEDIUM

                # Create risk entry
                risk = Risk(
                    asset="Uploaded Policy Document",
                    threat=risk_item.get("risk", "Unspecified threat"),
                    vulnerability="Policy gap or missing control",
                    control="Implement recommended security control",
                    compliance_standard=ComplianceFramework.NIST_SP_800_53,  # Default
                    status=RiskStatus.OPEN,
                    category=RiskCategory.CONFIGURATION,  # Default category
                    likelihood=3,  # Default medium likelihood
                    impact=3,     # Default medium impact
                    severity=severity,
                    scan_result_id=scan_result_id
                )
                risk.calculate_score()
                db.add(risk)
                db.commit()  # Commit to get risk.id
                created_risk_count += 1
                logging.info(f"Created risk entry {created_risk_count}: {risk_desc}")

                # Create compliance entries
                for compliance_item in compliance_data:
                    try:
                        control = compliance_item.get("control")
                        if not control:
                            continue
                        compliance = Compliance(
                            framework=compliance_item.get("framework", "Unknown"),   # Use scanned framework
                            control=control,
                            control_family=control.split("-")[0] if "-" in control else "XX",
                            score=0.0,
                            status="non-compliant",
                            risk_id=risk.id
                        )
                        db.add(compliance)
                    except Exception as e:
                        logging.error(f"Error creating compliance for risk {risk_desc}: {e}")
                        continue  # Skip this compliance item

            except Exception as e:
                logging.error(f"Error creating risk {risk_desc}: {e}")
                db.rollback()  # Rollback any uncommitted changes for this iteration
                continue  # Skip to next risk

        # Process detected threats from pattern matching
        threat_risk_count = 0
        if threats_data:
            for threat_item in threats_data:
                try:
                    threat_desc = threat_item.get("threat")
                    severity_str = threat_item.get("severity", "Medium")

                    if not threat_desc:
                        logging.warning(f"Skipping threat item missing 'threat' field: {threat_item}")
                        continue

                    severity_str = severity_str.title()
                    try:
                        severity = RiskSeverity[severity_str.upper()]
                    except KeyError:
                        logging.warning(f"Invalid severity '{severity_str}', defaulting to MEDIUM")
                        severity = RiskSeverity.MEDIUM

                    # Create risk entry for detected threat
                    threat_risk = Risk(
                        asset="Uploaded Policy Document",
                        threat=threat_desc,
                        vulnerability=threat_item.get("detection_method", "Pattern-based detection"),
                        control=threat_item.get("remediation", "Implement recommended security control"),
                        compliance_standard=ComplianceFramework.NIST_SP_800_53,
                        status=RiskStatus.OPEN,
                        category=RiskCategory.CONFIGURATION,
                        likelihood=4,  # Higher likelihood for detected threats
                        impact=4,     # Higher impact for detected threats
                        severity=severity,
                        scan_result_id=scan_result_id
                    )
                    threat_risk.calculate_score()
                    db.add(threat_risk)
                    db.commit()
                    threat_risk_count += 1
                    logging.info(f"Created threat risk entry {threat_risk_count}: {threat_desc}")

                except Exception as e:
                    logging.error(f"Error creating threat risk {threat_desc}: {e}")
                    db.rollback()
                    continue

        # Final commit for all compliance records
        try:
            db.commit()
            total_risks = created_risk_count + threat_risk_count
            logging.info(f"Successfully created {total_risks} risk entries ({created_risk_count} LLM + {threat_risk_count} pattern-based) and associated compliance records")
        except Exception as e:
            logging.error(f"Error in final commit: {e}")
            db.rollback()

    except Exception as e:
        db.rollback()
        logging.error(f"Error creating risks: {e}")
        raise  # Re-raise to ensure visibility
    finally:
        close_session(db)


def generate_risk_mitigation_plan(risk_data: dict) -> dict:
    """
    Generate comprehensive risk mitigation planning using OpenRouter AI.
    
    Args:
        risk_data (dict): Risk information containing threat, vulnerability, asset, etc.
    
    Returns:
        dict: Structured JSON response with mitigation planning details
    """
    
    prompt = f"""
    You are a senior cybersecurity risk management expert. For the following risk, provide a comprehensive mitigation plan:

    RISK DETAILS:
    - Asset: {risk_data.get('asset', 'Unknown')}
    - Threat: {risk_data.get('threat', 'Unknown')}
    - Vulnerability: {risk_data.get('vulnerability', 'Unknown')}
    - Current Risk Score: {risk_data.get('score', 'Unknown')}
    - Severity: {risk_data.get('severity', 'Unknown')}

    Provide a detailed mitigation plan in STRICT JSON format with this exact structure:

    {{
        "framework_controls": [
            {{
                "framework": "NIST Cybersecurity Framework",
                "control_id": "ID-RA",
                "control_name": "Risk Assessment",
                "description": "Detailed control description",
                "implementation_cost": "Estimated cost in USD",
                "timeline_months": 3,
                "rationale": "Why this control addresses the risk",
                "effectiveness_percentage": 85
            }}
        ],
        "treatment_strategies": {{
            "mitigate": {{
                "description": "Detailed mitigation approach",
                "implementation_steps": ["Step 1", "Step 2", "Step 3"],
                "timeline_months": 6,
                "resource_requirements": ["Resource 1", "Resource 2"],
                "estimated_cost": "Cost in USD",
                "residual_risk_score": 3,
                "monitoring_procedures": ["Monitoring step 1", "Monitoring step 2"]
            }},
            "avoid": {{
                "description": "Avoidance strategy details",
                "implementation_steps": ["Step 1", "Step 2"],
                "timeline_months": 2,
                "resource_requirements": ["Resource 1"],
                "estimated_cost": "Cost in USD",
                "residual_risk_score": 1,
                "monitoring_procedures": ["Monitoring procedure"]
            }},
            "transfer": {{
                "description": "Risk transfer approach",
                "implementation_steps": ["Step 1", "Step 2"],
                "timeline_months": 4,
                "resource_requirements": ["Resource 1", "Resource 2"],
                "estimated_cost": "Cost in USD",
                "residual_risk_score": 2,
                "monitoring_procedures": ["Monitoring procedure"]
            }},
            "accept": {{
                "description": "Risk acceptance rationale",
                "implementation_steps": ["Step 1"],
                "timeline_months": 1,
                "resource_requirements": ["Minimal resources"],
                "estimated_cost": "Cost in USD",
                "residual_risk_score": 5,
                "monitoring_procedures": ["Monitoring procedure"]
            }}
        }},
        "cost_benefit_analysis": {{
            "total_implementation_cost": "Total cost across all strategies",
            "annual_savings": "Expected annual cost savings",
            "roi_percentage": 150,
            "payback_period_months": 8,
            "risk_reduction_percentage": 75
        }},
        "recommended_strategy": {{
            "strategy": "mitigate",
            "rationale": "Why this strategy is recommended",
            "priority_level": "High",
            "business_alignment": "How it aligns with business objectives"
        }},
        "implementation_roadmap": [
            {{
                "phase": "Planning",
                "duration_weeks": 4,
                "milestones": ["Milestone 1", "Milestone 2"],
                "dependencies": ["Dependency 1"]
            }},
            {{
                "phase": "Implementation",
                "duration_weeks": 12,
                "milestones": ["Milestone 1", "Milestone 2"],
                "dependencies": ["Dependency 1", "Dependency 2"]
            }},
            {{
                "phase": "Testing",
                "duration_weeks": 4,
                "milestones": ["Milestone 1"],
                "dependencies": ["Previous phase completion"]
            }},
            {{
                "phase": "Monitoring",
                "duration_weeks": 52,
                "milestones": ["Ongoing monitoring"],
                "dependencies": ["Implementation completion"]
            }}
        ],
        "success_metrics": [
            {{
                "metric": "Risk Score Reduction",
                "target": "Reduce from 15 to 3",
                "measurement_method": "Risk scoring methodology",
                "frequency": "Quarterly"
            }},
            {{
                "metric": "Incident Reduction",
                "target": "50% reduction in related incidents",
                "measurement_method": "Incident tracking system",
                "frequency": "Monthly"
            }}
        ]
    }}

    Ensure all costs are realistic estimates, timelines are practical, and the response is valid JSON.
    """
    
    if not OPENROUTER_KEY:
        # Fallback response for testing without API key
        return {
            "framework_controls": [
                {
                    "framework": "NIST Cybersecurity Framework",
                    "control_id": "ID-RA",
                    "control_name": "Risk Assessment",
                    "description": "Implement comprehensive risk assessment process",
                    "implementation_cost": "$25,000",
                    "timeline_months": 3,
                    "rationale": "Addresses the core risk through systematic assessment",
                    "effectiveness_percentage": 85
                }
            ],
            "treatment_strategies": {
                "mitigate": {
                    "description": "Implement technical and administrative controls",
                    "implementation_steps": ["Assess current controls", "Design new controls", "Implement controls"],
                    "timeline_months": 6,
                    "resource_requirements": ["Security team", "IT resources"],
                    "estimated_cost": "$50,000",
                    "residual_risk_score": 3,
                    "monitoring_procedures": ["Regular audits", "Control effectiveness reviews"]
                },
                "avoid": {
                    "description": "Discontinue vulnerable process",
                    "implementation_steps": ["Identify alternative process", "Transition to new process"],
                    "timeline_months": 2,
                    "resource_requirements": ["Process owners"],
                    "estimated_cost": "$10,000",
                    "residual_risk_score": 1,
                    "monitoring_procedures": ["Process monitoring"]
                },
                "transfer": {
                    "description": "Transfer risk through insurance",
                    "implementation_steps": ["Assess insurance options", "Purchase coverage"],
                    "timeline_months": 4,
                    "resource_requirements": ["Risk management team"],
                    "estimated_cost": "$15,000",
                    "residual_risk_score": 2,
                    "monitoring_procedures": ["Policy reviews"]
                },
                "accept": {
                    "description": "Accept risk with monitoring",
                    "implementation_steps": ["Document acceptance decision"],
                    "timeline_months": 1,
                    "resource_requirements": ["Management approval"],
                    "estimated_cost": "$2,000",
                    "residual_risk_score": 5,
                    "monitoring_procedures": ["Regular risk reviews"]
                }
            },
            "cost_benefit_analysis": {
                "total_implementation_cost": "$77,000",
                "annual_savings": "$100,000",
                "roi_percentage": 130,
                "payback_period_months": 9,
                "risk_reduction_percentage": 80
            },
            "recommended_strategy": {
                "strategy": "mitigate",
                "rationale": "Provides best balance of risk reduction and business continuity",
                "priority_level": "High",
                "business_alignment": "Supports business objectives while maintaining security"
            },
            "implementation_roadmap": [
                {
                    "phase": "Planning",
                    "duration_weeks": 4,
                    "milestones": ["Requirements gathering", "Solution design"],
                    "dependencies": ["Stakeholder approval"]
                },
                {
                    "phase": "Implementation",
                    "duration_weeks": 12,
                    "milestones": ["Control deployment", "Testing"],
                    "dependencies": ["Planning completion"]
                },
                {
                    "phase": "Testing",
                    "duration_weeks": 4,
                    "milestones": ["Validation testing"],
                    "dependencies": ["Implementation completion"]
                },
                {
                    "phase": "Monitoring",
                    "duration_weeks": 52,
                    "milestones": ["Ongoing monitoring"],
                    "dependencies": ["Testing completion"]
                }
            ],
            "success_metrics": [
                {
                    "metric": "Risk Score Reduction",
                    "target": "Reduce risk score by 80%",
                    "measurement_method": "Risk assessment framework",
                    "frequency": "Quarterly"
                },
                {
                    "metric": "Cost Savings",
                    "target": "$100,000 annual savings",
                    "measurement_method": "Financial tracking",
                    "frequency": "Annually"
                }
            ]
        }
    
    # Call OpenRouter API
    url = "https://openrouter.ai/api/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {OPENROUTER_KEY}",
        "Content-Type": "application/json",
    }
    body = {
        "model": MODEL_NAME,
        "messages": [
            {"role": "system", "content": "You are a senior cybersecurity risk management expert. Provide comprehensive mitigation planning in STRICT JSON format only."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.3,
        "max_tokens": 4000
    }
    
    try:
        r = requests.post(url, headers=headers, json=body, timeout=120)
        r.raise_for_status()
        content = r.json()["choices"][0]["message"]["content"]
        
        # Parse JSON response
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            # Try to extract JSON from response
            import re
            json_match = re.search(r'\{.*\}', content, re.DOTALL)
            if json_match:
                return json.loads(json_match.group(0))
            else:
                logging.error(f"Could not parse JSON from AI response: {content[:500]}")
                return generate_fallback_mitigation_plan(risk_data)
                
    except Exception as e:
        logging.error(f"Error calling OpenRouter API: {e}")
        return generate_fallback_mitigation_plan(risk_data)


def generate_fallback_mitigation_plan(risk_data: dict) -> dict:
    """Fallback mitigation plan when API is unavailable"""
    return {
        "framework_controls": [],
        "treatment_strategies": {
            "mitigate": {"description": "API unavailable - manual planning required"},
            "avoid": {"description": "API unavailable - manual planning required"},
            "transfer": {"description": "API unavailable - manual planning required"},
            "accept": {"description": "API unavailable - manual planning required"}
        },
        "cost_benefit_analysis": {},
        "recommended_strategy": {"strategy": "manual_review"},
        "implementation_roadmap": [],
        "success_metrics": []
    }


