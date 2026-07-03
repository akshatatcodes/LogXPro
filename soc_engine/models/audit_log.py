"""
models/audit_log.py
--------------------
Phase 6: Audit log writer for SOC Engine events.

Records every significant action with enough detail to satisfy
SOC2 / HIPAA / PCI evidence requirements:
  - Which rule or playbook fired
  - Which basket was involved
  - What data was used (tier, techniques)
  - Who took action and when (analyst or automation)

Uses an existing PostgreSQL connection — does NOT open its own connection,
so it can be called inside existing transaction contexts safely.
"""
import json
from datetime import datetime, timezone


def _log_event(pg_conn, event_type: str, basket_id: str = None, rule_id: str = None,
               tier: str = None, actor: str = "system", detail: dict = None):
    """Internal helper that writes a single audit log entry."""
    try:
        with pg_conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO audit_log (event_type, basket_id, rule_id, tier, actor, detail, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, NOW())
                RETURNING id;
                """,
                (
                    event_type,
                    str(basket_id) if basket_id else None,
                    rule_id,
                    tier,
                    actor,
                    json.dumps(detail or {}, default=str)
                )
            )
            row = cur.fetchone()
        pg_conn.commit()
        return row["id"] if row else None
    except Exception as e:
        print(f"[!] Audit log write error ({event_type}): {e}")
        return None


def log_alert_fired(pg_conn, basket_id: str, rule_id: str, tier: str,
                    chain_name: str = None, confidence: int = 0):
    """
    Logs that an alert was fired.

    Args:
        pg_conn: Active PostgreSQL connection.
        basket_id: Incident basket UUID.
        rule_id: The Sigma rule or anomaly rule that triggered.
        tier: Alert tier (low, medium, high, critical).
        chain_name: The matched attack chain name, if applicable.
        confidence: Confidence score (0-100).
    """
    return _log_event(
        pg_conn,
        event_type="alert_fired",
        basket_id=basket_id,
        rule_id=rule_id,
        tier=tier,
        actor="engine",
        detail={
            "chain_name": chain_name,
            "confidence": confidence,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    )


def log_response_action(pg_conn, basket_id: str, action_type: str,
                        actor: str = "analyst", detail: dict = None):
    """
    Logs a response action taken on a basket (block IP, FP marking, etc.).

    Args:
        pg_conn: Active PostgreSQL connection.
        basket_id: Incident basket UUID.
        action_type: e.g. 'ip_block', 'false_positive', 'suppression_created'.
        actor: Who triggered the action (analyst name, webhook, playbook ID).
        detail: Additional context dict.
    """
    return _log_event(
        pg_conn,
        event_type=f"response_action:{action_type}",
        basket_id=basket_id,
        actor=actor,
        detail=detail or {}
    )


def log_suppression(pg_conn, host_name: str, user_name: str, rule_id: str,
                    suppressed_by: str, expires_in_seconds: int = 604800):
    """
    Logs the creation of an alert suppression rule.

    Args:
        pg_conn: Active PostgreSQL connection.
        host_name: The host the suppression applies to.
        user_name: The user the suppression applies to.
        rule_id: The rule being suppressed.
        suppressed_by: Who suppressed it (analyst or 'thehive_webhook').
        expires_in_seconds: How long the suppression is valid.
    """
    return _log_event(
        pg_conn,
        event_type="suppression_created",
        rule_id=rule_id,
        actor=suppressed_by,
        detail={
            "host_name": host_name,
            "user_name": user_name,
            "expires_in_seconds": expires_in_seconds,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    )


def log_playbook_fired(pg_conn, basket_id: str, playbook_id: str, tier: str,
                       actions_taken: list, auto_response: bool = False):
    """
    Logs that a playbook was matched and executed.

    Args:
        pg_conn: Active PostgreSQL connection.
        basket_id: Incident basket UUID.
        playbook_id: The ID of the fired playbook.
        tier: Alert tier.
        actions_taken: List of action type strings that were executed.
        auto_response: Whether auto-response was triggered.
    """
    return _log_event(
        pg_conn,
        event_type="playbook_fired",
        basket_id=basket_id,
        tier=tier,
        actor=f"playbook:{playbook_id}",
        detail={
            "playbook_id": playbook_id,
            "actions_taken": actions_taken,
            "auto_response_triggered": auto_response,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    )


def get_recent_audit_log(pg_conn, limit: int = 100) -> list[dict]:
    """
    Retrieves recent audit log entries from the database.

    Args:
        pg_conn: Active PostgreSQL connection.
        limit: Maximum number of entries to return.

    Returns:
        List of audit log entry dicts.
    """
    try:
        with pg_conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, event_type, basket_id, rule_id, tier, actor, detail, created_at
                FROM audit_log
                ORDER BY created_at DESC
                LIMIT %s;
                """,
                (limit,)
            )
            rows = cur.fetchall()
            result = []
            for row in rows:
                r = dict(row)
                r["basket_id"] = str(r["basket_id"]) if r["basket_id"] else None
                r["created_at"] = r["created_at"].isoformat() if r["created_at"] else None
                if isinstance(r["detail"], str):
                    try:
                        r["detail"] = json.loads(r["detail"])
                    except Exception:
                        pass
                result.append(r)
            return result
    except Exception as e:
        print(f"[!] Audit log read error: {e}")
        return []
