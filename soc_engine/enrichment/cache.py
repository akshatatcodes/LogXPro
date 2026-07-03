"""
enrichment/cache.py
-------------------
Phase 3: Caches enrichment results in PostgreSQL to protect free API quotas.

Every VirusTotal / AbuseIPDB check is cached here for CACHE_TTL_HOURS.
On a cache hit the real API is never called.
"""
import json
from datetime import datetime, timedelta

CACHE_TTL_HOURS = 24


def get_cached_result(pg_conn, indicator: str, source: str):
    """
    Returns cached verdict dict if a fresh result exists, else None.

    Args:
        pg_conn:    psycopg2 connection (with RealDictCursor).
        indicator:  IP address, domain, or file hash.
        source:     'virustotal' | 'abuseipdb' | 'misp'
    """
    try:
        with pg_conn.cursor() as cur:
            cur.execute(
                "SELECT verdict, checked_at FROM enrichment_cache "
                "WHERE indicator = %s AND source = %s",
                (indicator, source),
            )
            row = cur.fetchone()

        if row:
            age = datetime.utcnow() - row["checked_at"].replace(tzinfo=None)
            if age < timedelta(hours=CACHE_TTL_HOURS):
                return row["verdict"]  # Cache hit

    except Exception as e:
        print(f"[!] Cache read error ({indicator}@{source}): {e}")

    return None  # Cache miss


def set_cached_result(
    pg_conn,
    indicator: str,
    indicator_type: str,
    source: str,
    verdict: dict,
):
    """
    Writes or updates an enrichment result in the cache.

    Args:
        pg_conn:        psycopg2 connection.
        indicator:      The raw indicator value.
        indicator_type: 'ip' | 'domain' | 'hash'
        source:         'virustotal' | 'abuseipdb' | 'misp'
        verdict:        Dict of results to cache.
    """
    try:
        verdict_json = json.dumps(verdict)
        with pg_conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO enrichment_cache
                    (indicator, indicator_type, source, verdict, checked_at)
                VALUES (%s, %s, %s, %s, NOW())
                ON CONFLICT (indicator, source)
                DO UPDATE SET verdict = %s, checked_at = NOW()
                """,
                (indicator, indicator_type, source, verdict_json, verdict_json),
            )
        pg_conn.commit()
    except Exception as e:
        print(f"[!] Cache write error ({indicator}@{source}): {e}")
