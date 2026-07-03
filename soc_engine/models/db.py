import json
import psycopg2
from psycopg2.extras import RealDictCursor
from soc_engine.config.settings import settings

def get_db_connection():
    return psycopg2.connect(
        host=settings.DB_HOST,
        port=settings.DB_PORT,
        database=settings.DB_NAME,
        user=settings.DB_USER,
        password=settings.DB_PASSWORD,
        cursor_factory=RealDictCursor
    )

def create_basket(host_name: str, user_name: str = None, source_ip: str = None):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO incident_baskets (host_name, user_name, source_ip, status)
                VALUES (%s, %s, %s, 'open')
                RETURNING basket_id, host_name, user_name, source_ip, status, confidence_score, matched_stages, created_at, updated_at;
                """,
                (host_name, user_name, source_ip)
            )
            basket = cur.fetchone()
            conn.commit()
            return basket
    finally:
        conn.close()

def get_basket(basket_id: str):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM incident_baskets WHERE basket_id = %s;",
                (basket_id,)
            )
            return cur.fetchone()
    finally:
        conn.close()

def get_open_baskets():
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM incident_baskets WHERE status = 'open';")
            return cur.fetchall()
    finally:
        conn.close()

def update_basket_confidence(basket_id: str, confidence_score: int, matched_stages: list):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE incident_baskets
                SET confidence_score = %s, matched_stages = %s, updated_at = NOW()
                WHERE basket_id = %s
                RETURNING *;
                """,
                (confidence_score, json.dumps(matched_stages), basket_id)
            )
            basket = cur.fetchone()
            conn.commit()
            return basket
    finally:
        conn.close()

def close_basket(basket_id: str, status: str = 'closed'):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE incident_baskets SET status = %s, updated_at = NOW() WHERE basket_id = %s RETURNING *;",
                (status, basket_id)
            )
            basket = cur.fetchone()
            conn.commit()
            return basket
    finally:
        conn.close()

def add_event_to_basket(basket_id: str, event_type: str, raw_event: dict, mitre_technique: str = None, event_time = None, ingestion_time = None):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO basket_events (basket_id, event_type, raw_event, mitre_technique, event_time, ingestion_time)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING *;
                """,
                (basket_id, event_type, json.dumps(raw_event), mitre_technique, event_time, ingestion_time)
            )
            event = cur.fetchone()
            conn.commit()
            return event
    finally:
        conn.close()

def get_basket_events(basket_id: str):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM basket_events WHERE basket_id = %s ORDER BY ingestion_time ASC;", (basket_id,))
            return cur.fetchall()
    finally:
        conn.close()

def is_alert_suppressed(host_name: str, user_name: str, rule_id: str) -> bool:
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT EXISTS(
                    SELECT 1 FROM alert_suppression
                    WHERE (host_name IS NULL OR host_name = %s)
                      AND (user_name IS NULL OR user_name = %s)
                      AND (rule_id IS NULL OR rule_id = %s)
                      AND (expires_at IS NULL OR expires_at > NOW())
                );
                """,
                (host_name, user_name, rule_id)
            )
            return cur.fetchone()['exists']
    finally:
        conn.close()

def create_suppression(host_name: str = None, user_name: str = None, rule_id: str = None, suppressed_by: str = "analyst", expires_in_seconds: int = 604800):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO alert_suppression (host_name, user_name, rule_id, suppressed_by, expires_at)
                VALUES (%s, %s, %s, %s, NOW() + make_interval(secs => %s))
                RETURNING *;
                """,
                (host_name, user_name, rule_id, suppressed_by, expires_in_seconds)
            )
            suppression = cur.fetchone()
            conn.commit()
            return suppression
    finally:
        conn.close()

def get_open_basket_for_host(host_name: str, user_name: str = None):
    """Retrieves the active open basket for the host name and user name context."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT * FROM incident_baskets
                WHERE host_name = %s
                  AND user_name IS NOT DISTINCT FROM %s
                  AND status = 'open'
                LIMIT 1;
                """,
                (host_name, user_name)
            )
            return cur.fetchone()
    finally:
        conn.close()

def expire_old_open_baskets(max_age_minutes: int = 10):
    """Closes any open basket older than max_age_minutes with no new activity."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE incident_baskets
                SET status = 'expired', updated_at = NOW()
                WHERE status = 'open'
                  AND updated_at < NOW() - make_interval(mins => %s);
                """,
                (max_age_minutes,)
            )
            count = cur.rowcount
            conn.commit()
            if count:
                print(f"[*] Expired {count} stale open basket(s).")
    except Exception as e:
        print(f"[!] Error expiring stale open baskets: {e}")
    finally:
        conn.close()
