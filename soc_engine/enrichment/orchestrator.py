"""
enrichment/orchestrator.py
--------------------------
Orchestrates enrichment of indicators (IPs, domains, hashes) for alert baskets.
"""
from soc_engine.enrichment.indicator_parser import extract_indicators_from_basket
from soc_engine.enrichment.virustotal import check_ip as check_ip_vt, check_hash as check_hash_vt, check_domain as check_domain_vt
from soc_engine.enrichment.abuseipdb import check_ip as check_ip_abuseipdb
from soc_engine.enrichment.misp_client import check_indicator as check_misp


def enrich_basket(pg_conn, basket_id: str, basket_events: list = None) -> dict:
    """
    Enriches all indicators found in a basket.

    Args:
        pg_conn:        psycopg2 database connection (can be None in simulation).
        basket_id:      UUID/identifier of the basket.
        basket_events:  Optional pre-fetched list of events. If None, queries database.

    Returns:
        A dictionary mapping indicators to their unified threat intelligence verdicts:
        {
            "indicator": {
                "virustotal": {...},
                "abuseipdb": {...},
                "misp": {...}
            }
        }
    """
    # 1. Fetch events if not provided
    if not basket_events and pg_conn and basket_id:
        try:
            import soc_engine.models.db as db
            basket_events = db.get_basket_events(basket_id)
        except Exception as e:
            print(f"[!] Orchestrator: Failed to fetch events for basket {basket_id}: {e}")
            basket_events = []

    if not basket_events:
        basket_events = []

    # 2. Extract indicators
    indicators = extract_indicators_from_basket(basket_events)
    enrichment = {}

    # Mock data helper for simulation/offline mode
    def get_mock_enrichment(indicator: str, ind_type: str) -> dict:
        if indicator == "203.0.113.99":
            return {
                "virustotal": {
                    "malicious": 14,
                    "suspicious": 2,
                    "total": 72,
                    "country": "US",
                    "asn": 16509,
                    "note": "Simulated C2 server detection"
                },
                "abuseipdb": {
                    "abuse_score": 85,
                    "total_reports": 412,
                    "country": "US",
                    "domain": "amazonaws.com",
                    "isp": "Amazon.com, Inc.",
                    "is_tor": False,
                    "note": "Simulated high abuse score"
                },
                "misp": {
                    "found": True,
                    "event_count": 1,
                    "tags": ["Type:OSINT", "tlp:white", "threat_actor:CobaltGroup", "adversary:Cobalt Strike"]
                }
            }
        elif ind_type == "hash":
            return {
                "virustotal": {
                    "malicious": 58,
                    "suspicious": 1,
                    "total": 70,
                    "name": "mimikatz.exe",
                    "type": "Win32 EXE",
                    "note": "Simulated Mimikatz credential dumper"
                },
                "misp": {
                    "found": True,
                    "event_count": 3,
                    "tags": ["misp:malware-type=\"Credential Stealer\"", "threat_level:high"]
                }
            }
        elif ind_type == "domain":
            return {
                "virustotal": {
                    "malicious": 4,
                    "suspicious": 0,
                    "total": 68,
                    "registrar": "NameCheap, Inc.",
                    "creation_date": 1609459200
                },
                "misp": {
                    "found": False
                }
            }
        return None

    # 3. Enrich IPs
    for ip in indicators.get("ips", []):
        mock_val = get_mock_enrichment(ip, "ip")
        if mock_val and (not pg_conn or not settings.VT_API_KEY or not settings.ABUSEIPDB_API_KEY):
            enrichment[ip] = mock_val
            continue

        ip_data = {}
        # VirusTotal
        try:
            ip_data["virustotal"] = check_ip_vt(pg_conn, ip) if pg_conn else {"error": "Offline"}
        except Exception as e:
            ip_data["virustotal"] = {"error": str(e)}

        # AbuseIPDB
        try:
            ip_data["abuseipdb"] = check_ip_abuseipdb(pg_conn, ip) if pg_conn else {"error": "Offline"}
        except Exception as e:
            ip_data["abuseipdb"] = {"error": str(e)}

        # MISP
        try:
            ip_data["misp"] = check_misp(pg_conn, ip, "ip") if pg_conn else {"error": "Offline"}
        except Exception as e:
            ip_data["misp"] = {"error": str(e)}

        enrichment[ip] = ip_data

    # 4. Enrich file hashes
    for h in indicators.get("hashes", []):
        mock_val = get_mock_enrichment(h, "hash")
        if mock_val and (not pg_conn or not settings.VT_API_KEY):
            enrichment[h] = mock_val
            continue

        hash_data = {}
        # VirusTotal
        try:
            hash_data["virustotal"] = check_hash_vt(pg_conn, h) if pg_conn else {"error": "Offline"}
        except Exception as e:
            hash_data["virustotal"] = {"error": str(e)}

        # MISP
        try:
            hash_data["misp"] = check_misp(pg_conn, h, "hash") if pg_conn else {"error": "Offline"}
        except Exception as e:
            hash_data["misp"] = {"error": str(e)}

        enrichment[h] = hash_data

    # 5. Enrich DNS domains
    for d in indicators.get("domains", []):
        mock_val = get_mock_enrichment(d, "domain")
        if mock_val and (not pg_conn or not settings.VT_API_KEY):
            enrichment[d] = mock_val
            continue

        domain_data = {}
        # VirusTotal
        try:
            domain_data["virustotal"] = check_domain_vt(pg_conn, d) if pg_conn else {"error": "Offline"}
        except Exception as e:
            domain_data["virustotal"] = {"error": str(e)}

        # MISP
        try:
            domain_data["misp"] = check_misp(pg_conn, d, "domain") if pg_conn else {"error": "Offline"}
        except Exception as e:
            domain_data["misp"] = {"error": str(e)}

        enrichment[d] = domain_data

    return enrichment
