"""
enrichment/virustotal.py
------------------------
Phase 3: VirusTotal free public API wrapper.

Free tier: 4 requests/minute, 500 requests/day.
All results are cached via enrichment/cache.py to protect the quota.
"""
import requests
from soc_engine.config.settings import settings
from soc_engine.enrichment.cache import get_cached_result, set_cached_result

VT_BASE = "https://www.virustotal.com/api/v3"


def check_ip(pg_conn, ip: str) -> dict:
    """
    Looks up an IP address on VirusTotal.
    Returns the cached result if available, otherwise calls the API.

    Returns:
        {
            "malicious": int,   # Number of AV vendors flagging as malicious
            "total": int,       # Total vendors checked
            "country": str,
            "asn": int,
        }
    """
    cached = get_cached_result(pg_conn, ip, "virustotal")
    if cached:
        return cached

    api_key = settings.VT_API_KEY
    if not api_key:
        return {"error": "VT_API_KEY not configured", "malicious": 0, "total": 0}

    try:
        resp = requests.get(
            f"{VT_BASE}/ip_addresses/{ip}",
            headers={"x-apikey": api_key},
            timeout=10,
        ).json()

        attrs = resp.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        verdict = {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "total": sum(stats.values()),
            "country": attrs.get("country"),
            "asn": attrs.get("asn"),
        }
        set_cached_result(pg_conn, ip, "ip", "virustotal", verdict)
        return verdict

    except Exception as e:
        return {"error": str(e), "malicious": 0, "total": 0}


def check_hash(pg_conn, file_hash: str) -> dict:
    """Looks up a file hash (MD5/SHA1/SHA256) on VirusTotal."""
    cached = get_cached_result(pg_conn, file_hash, "virustotal")
    if cached:
        return cached

    api_key = settings.VT_API_KEY
    if not api_key:
        return {"error": "VT_API_KEY not configured", "malicious": 0, "total": 0}

    try:
        resp = requests.get(
            f"{VT_BASE}/files/{file_hash}",
            headers={"x-apikey": api_key},
            timeout=10,
        ).json()

        attrs = resp.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        verdict = {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "total": sum(stats.values()),
            "name": attrs.get("meaningful_name"),
            "type": attrs.get("type_description"),
        }
        set_cached_result(pg_conn, file_hash, "hash", "virustotal", verdict)
        return verdict

    except Exception as e:
        return {"error": str(e), "malicious": 0, "total": 0}


def check_domain(pg_conn, domain: str) -> dict:
    """Looks up a domain name on VirusTotal."""
    cached = get_cached_result(pg_conn, domain, "virustotal")
    if cached:
        return cached

    api_key = settings.VT_API_KEY
    if not api_key:
        return {"error": "VT_API_KEY not configured", "malicious": 0, "total": 0}

    try:
        resp = requests.get(
            f"{VT_BASE}/domains/{domain}",
            headers={"x-apikey": api_key},
            timeout=10,
        ).json()

        attrs = resp.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        verdict = {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "total": sum(stats.values()),
            "registrar": attrs.get("registrar"),
            "creation_date": attrs.get("creation_date"),
        }
        set_cached_result(pg_conn, domain, "domain", "virustotal", verdict)
        return verdict

    except Exception as e:
        return {"error": str(e), "malicious": 0, "total": 0}
