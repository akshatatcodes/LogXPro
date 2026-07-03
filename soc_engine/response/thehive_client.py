"""
response/thehive_client.py
--------------------------
Phase 5: Creates TheHive cases from confirmed alert payloads.

Requires TheHive running locally (e.g. via Docker on port 9000).
API Key is generated in the TheHive admin panel.
"""
import requests
from soc_engine.config.settings import settings

THEHIVE_URL = getattr(settings, "THEHIVE_URL", "http://localhost:9000")
THEHIVE_API_KEY = getattr(settings, "THEHIVE_API_KEY", "")

_SEVERITY_MAP = {
    "low":      1,
    "medium":   2,
    "high":     2,
    "critical": 3,
}


def create_case(alert: dict) -> dict | None:
    """
    Creates a TheHive case from a structured alert payload.

    Args:
        alert: Alert payload dict from tiering.build_alert_payload().

    Returns:
        TheHive API response dict, or None on failure.
    """
    if not THEHIVE_API_KEY:
        print("[!] TheHive: THEHIVE_API_KEY not configured. Skipping case creation.")
        return None

    tier = alert.get("tier", "medium")
    host = alert.get("host_name", "UNKNOWN")
    chain = alert.get("chain_name", "Unknown Chain")
    confidence = alert.get("confidence_score", 0)
    narrative = alert.get("ai_narrative") or "No narrative generated yet."

    case_payload = {
        "title": f"[{tier.upper()}] {chain} on {host}",
        "description": narrative,
        "severity": _SEVERITY_MAP.get(tier, 2),
        "tags": [
            chain,
            f"confidence:{confidence}%",
            f"host:{host}",
            f"tier:{tier}",
            f"basket:{alert.get('basket_id')}",
            f"rule:{alert.get('triggering_rule', {}).get('id')}",
            f"user:{alert.get('user_name')}",
        ],
        "tasks": [
            {"title": "Review AI-generated attack timeline"},
            {"title": "Verify enrichment results (VT / AbuseIPDB)"},
            {"title": "Approve or reject auto-response action"},
        ],
    }

    try:
        resp = requests.post(
            f"{THEHIVE_URL}/api/case",
            json=case_payload,
            headers={
                "Authorization": f"Bearer {THEHIVE_API_KEY}",
                "Content-Type": "application/json",
            },
            timeout=10,
        )
        resp.raise_for_status()
        case_data = resp.json()
        print(f"[+] TheHive case created: #{case_data.get('number')} — {case_data.get('title')}")
        return case_data

    except Exception as e:
        print(f"[!] TheHive case creation failed: {e}")
        return None
