# llm_scan.py
import json
import os
import re
from pathlib import Path

import requests
from PyPDF2 import PdfReader

MODEL_NAME = os.getenv("MODEL_NAME", "openai/gpt-oss-20b:free")
OPENROUTER_KEY = os.getenv("OPENROUTER_API_KEY", OPENROUTER_API_KEY)

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
    If you use a different provider, adjust URL/headers/fields accordingly.
    """
    if not OPENROUTER_KEY:
        # Safe fallback for local testing without a key
        return json.dumps({
            "summary": "Demo summary (no API key found).",
            "compliance_hits": [{"framework": "NIST SP 800-53", "control": "AC-2", "note": "Access control policy referenced."}],
            "risks": [{"risk": "Lack of formal incident response testing", "severity": "Medium"}],
            "other_notes": "Provide an API key to get real results."
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
    Returns a dict with keys: summary (str), compliance_hits (list), risks (list), other_notes (str).
    """
    text = _extract_text(file_path)

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
    return data
