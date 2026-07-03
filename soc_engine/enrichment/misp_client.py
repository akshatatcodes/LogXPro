"""
enrichment/misp_client.py
-------------------------
Phase 3: MISP local API wrapper.

Queries self-hosted MISP threat intelligence instance.
All queries are cached to protect execution times and avoid redundant load.
"""
import urllib3
from soc_engine.config.settings import settings
from soc_engine.enrichment.cache import get_cached_result, set_cached_result

# Disable PyMISP SSL verification warnings for local dev setups
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_misp_client():
    url = settings.MISP_URL
    key = settings.MISP_API_KEY
    if not key or not url:
        return None

    try:
        from pymisp import PyMISP
        # ssl=False allows local self-signed setups common in labs
        return PyMISP(url, key, ssl=False, debug=False)
    except Exception as e:
        print(f"[!] MISP client init failed: {e}")
        return None


def check_indicator(pg_conn, indicator: str, indicator_type: str) -> dict:
    """
    Looks up an indicator (IP, domain, or hash) in MISP.
    Returns the cached result if available.

    Args:
        pg_conn:        psycopg2 database connection.
        indicator:      The value to search (e.g. IP, domain, or file hash).
        indicator_type: 'ip' | 'domain' | 'hash'

    Returns:
        {
            "found": bool,
            "event_count": int,
            "tags": list[str],
        }
    """
    cached = get_cached_result(pg_conn, indicator, "misp")
    if cached is not None:
        return cached

    misp = get_misp_client()
    if not misp:
        # Graceful default when MISP is not configured or reachable
        return {"found": False, "note": "MISP not configured or offline"}

    try:
        result = misp.search(value=indicator, pythonify=True)
        if result:
            tags = []
            for event in result:
                # Retrieve attributes list dynamically to handle different PyMISP versions
                attrs = getattr(event, "attributes", []) or getattr(event, "Attribute", [])
                for attr in attrs:
                    val = getattr(attr, "value", None)
                    if val == indicator:
                        attr_tags = getattr(attr, "tags", []) or getattr(attr, "Tag", [])
                        for t in attr_tags:
                            t_name = getattr(t, "name", None) or str(t)
                            if t_name:
                                tags.append(t_name)

            verdict = {
                "found": True,
                "event_count": len(result),
                "tags": list(set(tags)),
            }
        else:
            verdict = {"found": False}

        set_cached_result(pg_conn, indicator, indicator_type, "misp", verdict)
        return verdict

    except Exception as e:
        print(f"[!] MISP search error for {indicator}: {e}")
        # Cache negative hit temporarily on connection failure to avoid retry loops
        return {"found": False, "error": str(e)}
