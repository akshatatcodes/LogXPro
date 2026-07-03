"""
enrichment/abuseipdb.py
-----------------------
Phase 3: AbuseIPDB free API wrapper.

Free tier: 1,000 checks/day.
All results are cached via enrichment/cache.py to protect the quota.
"""
import requests
from soc_engine.config.settings import settings
from soc_engine.enrichment.cache import get_cached_result, set_cached_result

ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"


def check_ip(pg_conn, ip: str, max_age_days: int = 90) -> dict:
    """
    Looks up an IP address on AbuseIPDB.
    Returns cached result if available.

    Args:
        pg_conn:       psycopg2 connection.
        ip:            IP address to look up.
        max_age_days:  Only count reports from this many days back (default 90).

    Returns:
        {
            "abuse_score": int,       # 0-100 confidence score
            "total_reports": int,
            "country": str,
            "domain": str,
            "isp": str,
            "is_tor": bool,
        }
    """
    cached = get_cached_result(pg_conn, ip, "abuseipdb")
    if cached:
        return cached

    api_key = settings.ABUSEIPDB_API_KEY
    if not api_key:
        return {"error": "ABUSEIPDB_API_KEY not configured", "abuse_score": 0}

    try:
        resp = requests.get(
            f"{ABUSEIPDB_BASE}/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": max_age_days},
            timeout=10,
        ).json()

        data = resp.get("data", {})
        verdict = {
            "abuse_score":    data.get("abuseConfidenceScore", 0),
            "total_reports":  data.get("totalReports", 0),
            "country":        data.get("countryCode"),
            "domain":         data.get("domain"),
            "isp":            data.get("isp"),
            "is_tor":         data.get("isTor", False),
            "last_reported":  data.get("lastReportedAt"),
        }
        set_cached_result(pg_conn, ip, "ip", "abuseipdb", verdict)
        return verdict

    except Exception as e:
        return {"error": str(e), "abuse_score": 0}
