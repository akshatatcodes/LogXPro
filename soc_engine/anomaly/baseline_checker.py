"""
anomaly/baseline_checker.py
---------------------------
Phase 5: Login baseline builder and anomaly detector.

Builds normal patterns per (user, source_ip) from successful login events.
Flags logins that deviate from baseline (new IP, off-hours, new country).

The anomaly findings are fed back into the basket correlation engine
as low-confidence initial events.
"""
from datetime import datetime


def update_baseline(pg_conn, user: str, source_ip: str, source_country: str, hour: int):
    """
    Updates the login_baseline table with a new successful login observation.
    Uses UPSERT logic: first ever entry creates the baseline,
    subsequent entries widen the typical_hour window and bump seen_count.

    Call this for every Event 4624 (Successful Logon) you receive.
    """
    try:
        with pg_conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO login_baseline
                    (user_name, source_ip, source_country,
                     typical_hour_start, typical_hour_end,
                     first_seen, last_seen, seen_count)
                VALUES (%s, %s, %s, %s, %s, NOW(), NOW(), 1)
                ON CONFLICT (user_name, source_ip) DO UPDATE SET
                    last_seen = NOW(),
                    seen_count = login_baseline.seen_count + 1,
                    typical_hour_start = LEAST(login_baseline.typical_hour_start, %s),
                    typical_hour_end   = GREATEST(login_baseline.typical_hour_end, %s)
                """,
                (user, source_ip, source_country, hour, hour, hour, hour),
            )
        pg_conn.commit()
    except Exception as e:
        print(f"[!] Baseline update error for {user}@{source_ip}: {e}")


def check_anomaly(
    pg_conn,
    user: str,
    source_ip: str,
    source_country: str,
    login_time: datetime,
) -> list[dict]:
    """
    Checks a login event against the established baseline for the user.

    Returns a list of anomaly dicts (empty list = no anomalies).
    Each anomaly has: type, description, confidence (0-100).

    Anomaly types:
        first_seen_ip   — Never seen this IP for this user.
        off_hours_login — Login outside the normal hour window.
        new_country     — Login from a different country than baseline.
    """
    anomalies = []
    hour = login_time.hour

    try:
        with pg_conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM login_baseline WHERE user_name = %s AND source_ip = %s",
                (user, source_ip),
            )
            row = cur.fetchone()
    except Exception as e:
        print(f"[!] Baseline read error: {e}")
        return []

    # Check 1: First-ever login from this IP
    if not row:
        anomalies.append({
            "type": "first_seen_ip",
            "description": f"First login from {source_ip} for user {user}",
            "confidence": 30,
        })
        return anomalies  # No further checks possible without a baseline

    # Check 2: Login outside normal hours
    if hour < row["typical_hour_start"] or hour > row["typical_hour_end"]:
        anomalies.append({
            "type": "off_hours_login",
            "description": (
                f"Login at {hour:02d}:00 UTC is outside the normal window "
                f"({row['typical_hour_start']:02d}:00–{row['typical_hour_end']:02d}:00)"
            ),
            "confidence": 40,
        })

    # Check 3: Login from a new country
    if source_country and source_country != row.get("source_country"):
        anomalies.append({
            "type": "new_country",
            "description": (
                f"Login from {source_country} — "
                f"baseline country is {row.get('source_country', 'unknown')}"
            ),
            "confidence": 60,
        })

    return anomalies
