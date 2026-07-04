"""
detection/tiering.py
--------------------
Confidence scoring engine and tiered alerting logic.

Tier Definitions:
    Tier 0  → Critical single event. Fire immediately. No basket required.
    Tier 1  → Low  (confidence 1–49%):  Watch and wait.
    Tier 2  → Medium (confidence 50–74%): Actionable alert — analyst review needed.
    Tier 3  → High  (confidence 75–99%): Escalate to SOAR/TheHive.
    Tier 4  → Critical (confidence 100%): Full attack chain confirmed.

Deduplication:
    Uses Redis TTL keys to suppress duplicate alert fires within a cooldown window.
    Prevents alert storms when the same rule matches repeatedly in quick succession.
"""
import json
import redis
from datetime import datetime, timezone
from typing import Optional

from soc_engine.config.settings import settings

# --------------------------------------------------------------------------- #
# Redis client (shared with basket_manager to save connections)                #
# --------------------------------------------------------------------------- #
try:
    _redis_client = redis.Redis(
        host=settings.REDIS_HOST,
        port=settings.REDIS_PORT,
        db=settings.REDIS_DB,
        password=settings.REDIS_PASSWORD or None,
        decode_responses=True,
        socket_connect_timeout=2,
    )
    _redis_client.ping()
    _redis_available = True
except Exception:
    _redis_client = None
    _redis_available = False

# --------------------------------------------------------------------------- #
# Constants                                                                     #
# --------------------------------------------------------------------------- #
DEDUP_WINDOW_SECONDS = int(getattr(settings, "DEDUP_WINDOW_SECONDS", 300))  # 5 min


# --------------------------------------------------------------------------- #
# Confidence scoring                                                            #
# --------------------------------------------------------------------------- #

def calculate_confidence(basket: dict, chain: dict) -> int:
    """
    Calculates a 0-100 confidence score for a basket relative to a chain.

    Score = (matched_stages / total_stages) * 100

    Args:
        basket: Basket dict with a 'matched_stages' key.
        chain:  Chain definition dict with a 'stages' key.

    Returns:
        Integer 0-100.
    """
    total_stages = len(chain.get("stages", []))
    if total_stages == 0:
        return 0

    matched_count = len(basket.get("matched_stages", []))
    return int((matched_count / total_stages) * 100)


def score_to_tier(score: int) -> Optional[str]:
    """
    Maps a confidence score to an alert tier string.

    Returns None if the score is 0 (nothing to alert on).
    """
    if score == 100:
        return "critical"
    elif score >= 75:
        return "high"
    elif score >= 50:
        return "medium"
    elif score >= 1:
        return "low"
    return None


def get_min_stages_for_alert(chain: dict) -> int:
    """
    Returns the minimum matched-stage count required to fire any alert.
    Defaults to 2 so we don't fire on a single isolated rule match.
    """
    return chain.get("min_stages_for_alert", 2)


# --------------------------------------------------------------------------- #
# Deduplication (prevents alert storms)                                        #
# --------------------------------------------------------------------------- #

def is_duplicate(host_name: str, rule_id: str, window_seconds: int = DEDUP_WINDOW_SECONDS) -> bool:
    """
    Checks whether this (host, rule) pair already fired within the dedup window.

    On a cache miss → sets the key (marks this as the first fire).
    On a cache hit  → increments a counter and returns True (suppress).

    Falls back to False (allow) if Redis is unavailable.

    Args:
        host_name:      The hostname key.
        rule_id:        The Sigma rule ID.
        window_seconds: Dedup suppression window in seconds.

    Returns:
        True  → duplicate, suppress this alert.
        False → new alert, allow it through.
    """
    if not _redis_available or _redis_client is None:
        return False  # No Redis → never suppress (safe fallback)

    dedup_key = f"dedup:{host_name}:{rule_id}"
    count_key = f"dedup_count:{host_name}:{rule_id}"

    try:
        existing = _redis_client.get(dedup_key)
        if existing:
            # Already fired recently — increment storm counter, suppress
            _redis_client.incr(count_key)
            _redis_client.expire(count_key, window_seconds)
            return True

        # First fire — set TTL key and allow
        _redis_client.setex(dedup_key, window_seconds, "1")
        return False

    except Exception as e:
        print(f"[!] Tiering: Redis dedup error: {e}")
        return False  # On error, allow (safe side for security)


def get_storm_count(host_name: str, rule_id: str) -> int:
    """
    Returns how many times this alert was suppressed by deduplication
    since the dedup window started.
    """
    if not _redis_available or _redis_client is None:
        return 0

    count_key = f"dedup_count:{host_name}:{rule_id}"
    try:
        val = _redis_client.get(count_key)
        return int(val) if val else 0
    except Exception:
        return 0


def reset_dedup(host_name: str, rule_id: str) -> None:
    """Manually clears the dedup key (e.g. used in tests)."""
    if not _redis_available or _redis_client is None:
        return
    try:
        _redis_client.delete(f"dedup:{host_name}:{rule_id}")
        _redis_client.delete(f"dedup_count:{host_name}:{rule_id}")
    except Exception:
        pass


# --------------------------------------------------------------------------- #
# Alert decision logic                                                          #
# --------------------------------------------------------------------------- #

def should_fire_alert(
    basket: dict,
    sigma_match: dict,
    chain: dict,
    eval_result: dict,
) -> tuple[Optional[str], Optional[str]]:
    """
    Central decision point: decides whether and at what tier to fire an alert.

    Priority order:
        1. Tier 0 (Instant)  — single-event critical Sigma rules bypass basket logic.
        2. Chain-based tiers — based on confidence score vs the matched chain.

    Args:
        basket:       Current basket dict.
        sigma_match:  The Sigma rule that just matched.
        chain:        The chain definition being evaluated.
        eval_result:  Output of chain_matcher.evaluate_basket() containing
                      'confidence', 'matched_stages', 'chain_name'.

    Returns:
        Tuple of (alert_type, tier_string) where alert_type is one of:
            'tier0_instant'   → Immediate critical single-rule alert.
            'tier_chain'      → Alert based on basket chain confidence.
            None              → No alert should be fired.
    """
    rule_level = sigma_match.get("level", "medium")
    host_name = basket.get("host_name", "UNKNOWN")
    rule_id = sigma_match.get("id", "UNKNOWN")

    # --- Tier 0: Critical single event ---
    if rule_level == "critical":
        if is_duplicate(host_name, rule_id):
            return None, None
        return "tier0_instant", "critical"

    # --- Chain-based tiered alerts ---
    confidence = eval_result.get("confidence", 0)
    matched_stages = eval_result.get("matched_stages", [])
    min_stages = get_min_stages_for_alert(chain)

    if len(matched_stages) < min_stages:
        # Not enough stages yet — wait for more evidence
        return None, None

    tier = score_to_tier(confidence)
    if tier is None:
        return None, None

    # Dedup check — suppress if same host+rule already fired in this window
    if is_duplicate(host_name, rule_id):
        storm_count = get_storm_count(host_name, rule_id)
        print(
            f"[=] Dedup suppressed: {rule_id} on {host_name} "
            f"(storm count: {storm_count}, window: {DEDUP_WINDOW_SECONDS}s)"
        )
        return None, None

    return "tier_chain", tier


# --------------------------------------------------------------------------- #
# Alert formatting helpers                                                      #
# --------------------------------------------------------------------------- #

_TIER_COLORS = {
    "critical": "\033[41m\033[97m",  # Red background, white text
    "high":     "\033[91m",          # Bright red
    "medium":   "\033[93m",          # Yellow
    "low":      "\033[96m",          # Cyan
}
_RESET = "\033[0m"



def format_alert_banner(
    alert_type: str,
    tier: str,
    basket: dict,
    eval_result: dict,
) -> str:
    """
    Formats a coloured terminal alert banner with full context.

    Args:
        alert_type:  'tier0_instant' or 'tier_chain'.
        tier:        'low', 'medium', 'high', 'critical'.
        basket:      Basket dict.
        eval_result: Chain evaluator output.

    Returns:
        A multi-line formatted alert string ready to print.
    """
    color = _TIER_COLORS.get(tier, "")
    reset = _RESET
    basket_id = str(basket.get("basket_id", "?"))[:8]
    host = basket.get("host_name", "UNKNOWN")
    user = basket.get("user_name") or "N/A"
    confidence = eval_result.get("confidence", 0)
    chain_name = eval_result.get("chain_name", "N/A")
    matched = eval_result.get("matched_stages", [])
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    lines = [
        "",
        "=" * 60,
    ]

    if alert_type == "tier0_instant":
        lines.append(f"{color}[!! TIER 0 -- INSTANT CRITICAL]{reset}")
        lines.append(f"  Single critical rule fired on {host}")
    else:
        tier_label = tier.upper()
        lines.append(f"{color}[** TIER CHAIN -- {tier_label}]{reset}")
        lines.append(f"  Chain: {chain_name}")
        lines.append(f"  Confidence: {confidence}%")

    lines += [
        f"  Host:  {host}",
        f"  User:  {user}",
        f"  Basket: {basket_id}...",
        f"  Time:  {now}",
    ]

    if matched:
        lines.append("  Matched Stages:")
        for s in matched:
            stage_num = s.get("stage", "?")
            mitre = s.get("mitre", "?")
            lines.append(f"    [{stage_num}] {mitre}")

    lines.append("=" * 60)
    return "\n".join(lines)


def build_alert_payload(
    basket: dict,
    eval_result: dict,
    alert_type: str,
    tier: str,
    sigma_match: dict,
) -> dict:
    """
    Builds a structured alert payload dict for storage/forwarding.
    This is the object that will be indexed into Elasticsearch 'soc-alerts'
    in Phase 4, and sent to TheHive in Phase 5.

    Args:
        basket:       Current basket state.
        eval_result:  Chain evaluation result.
        alert_type:   'tier0_instant' or 'tier_chain'.
        tier:         'low', 'medium', 'high', 'critical'.
        sigma_match:  The Sigma rule that triggered this alert.

    Returns:
        Dict ready for JSON serialization and ES indexing.
    """
    return {
        "basket_id": str(basket.get("basket_id", "")),
        "host_name": basket.get("host_name"),
        "user_name": basket.get("user_name"),
        "source_ip": basket.get("source_ip"),
        "alert_type": alert_type,
        "tier": tier,
        "confidence_score": eval_result.get("confidence", 0),
        "chain_id": eval_result.get("chain_id"),
        "chain_name": eval_result.get("chain_name"),
        "matched_stages": eval_result.get("matched_stages", []),
        "triggering_rule": {
            "id": sigma_match.get("id"),
            "title": sigma_match.get("title"),
            "level": sigma_match.get("level"),
            "mitre_techniques": sigma_match.get("mitre_techniques", []),
        },
        "status": "open",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        # Placeholders for Phase 3 (enrichment) and Phase 4 (AI narrative)
        "enrichment": None,
        "ai_narrative": None,
    }
