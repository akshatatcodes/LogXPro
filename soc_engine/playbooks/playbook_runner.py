"""
playbooks/playbook_runner.py
-----------------------------
Phase 6: Loads YAML playbook definitions and executes matching actions
based on alert tier and matched MITRE techniques.

Playbook YAML structure:
  id: unique_playbook_id
  name: Human-readable name
  trigger_tier: [1, 2, 3]           # which tiers trigger this
  matched_techniques: [T1059.001]   # MITRE IDs (empty = match any)
  matched_chain: phishing_c2        # or match by chain name (optional)
  actions:
    - type: notify
      message: "Review PowerShell execution on {host}"
    - type: recommend
      text: "Isolate {host} and reset {user} credentials."
    - type: auto_response
      enabled: false   # honoured only if GRC profile allows it
"""
import os
import glob
import yaml
from pathlib import Path

_PLAYBOOK_DIR = os.path.join(
    os.path.dirname(__file__), "..", "config", "playbooks"
)

_loaded_playbooks: list[dict] = []


def load_playbooks() -> list[dict]:
    """
    Loads all YAML playbook definitions from the config/playbooks/ directory.
    Returns a flat list of playbook dicts.
    """
    global _loaded_playbooks
    _loaded_playbooks = []

    pattern = os.path.join(os.path.abspath(_PLAYBOOK_DIR), "*.yaml")
    for filepath in glob.glob(pattern):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                pb = yaml.safe_load(f)
                if pb and isinstance(pb, dict):
                    _loaded_playbooks.append(pb)
        except Exception as e:
            print(f"[!] Failed to load playbook {filepath}: {e}")

    print(f"[*] Loaded {len(_loaded_playbooks)} playbook(s) from {_PLAYBOOK_DIR}")
    return _loaded_playbooks


def _tier_to_int(tier: str) -> int:
    """Maps tier string to integer for comparison."""
    return {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(tier.lower(), 1)


def _matches_playbook(playbook: dict, tier: str, techniques: list[str], chain_name: str) -> bool:
    """Returns True if the given alert context matches this playbook's triggers."""
    tier_int = _tier_to_int(tier)

    # Check trigger tier
    trigger_tiers = playbook.get("trigger_tier", [])
    if trigger_tiers and tier_int not in trigger_tiers:
        return False

    # Check MITRE techniques (if specified)
    required_techniques = playbook.get("matched_techniques", [])
    if required_techniques:
        if not any(t in techniques for t in required_techniques):
            return False

    # Check chain name (if specified)
    required_chain = playbook.get("matched_chain", "")
    if required_chain and required_chain.lower() not in chain_name.lower():
        return False

    return True


def run_playbook(payload: dict, grc_profile: dict = None) -> dict:
    """
    Evaluates all loaded playbooks against the alert payload and executes
    matching actions. Returns a playbook result dict.

    Args:
        payload: The alert payload from `build_alert_payload`.
        grc_profile: The active GRC profile dict (controls auto_response).

    Returns:
        dict with keys: matched_playbooks, recommendations, notifications,
                        auto_response_triggered, auto_response_allowed.
    """
    if not _loaded_playbooks:
        load_playbooks()

    tier = payload.get("tier", "low")
    chain_name = payload.get("chain_name", "")
    host = payload.get("host_name", "UNKNOWN")
    user = payload.get("user_name", "UNKNOWN")
    basket_id = payload.get("basket_id", "")

    # Collect all matched MITRE techniques from matched stages
    techniques = []
    for stage in payload.get("matched_stages", []):
        t = stage.get("mitre") or ""
        if t:
            techniques.append(t)
    rule = payload.get("triggering_rule", {})
    techniques.extend(rule.get("mitre_techniques", []))
    techniques = list(set(techniques))

    auto_response_globally_allowed = (grc_profile or {}).get("auto_response_allowed", False)

    result = {
        "matched_playbooks": [],
        "recommendations": [],
        "notifications": [],
        "auto_response_triggered": False,
        "auto_response_allowed": auto_response_globally_allowed,
    }

    for pb in _loaded_playbooks:
        if not _matches_playbook(pb, tier, techniques, chain_name):
            continue

        pb_id = pb.get("id", "unknown")
        pb_name = pb.get("name", pb_id)
        result["matched_playbooks"].append(pb_id)
        print(f"\n[PLAYBOOK] Matched: '{pb_name}' (ID: {pb_id})")

        for action in pb.get("actions", []):
            action_type = action.get("type", "")

            # --- notify ---
            if action_type == "notify":
                message = action.get("message", "").format(
                    host=host, user=user, tier=tier.upper(), chain=chain_name
                )
                severity = action.get("severity", tier)
                print(f"  [NOTIFY] [{severity.upper()}] {message}")

                # Optional: fire webhook (Slack/Teams)
                webhook_url = os.getenv("WEBHOOK_URL", "")
                if webhook_url and message:
                    try:
                        import requests
                        requests.post(webhook_url, json={"text": f"[LogXPro] {message}"}, timeout=5)
                        print(f"  [+] Notification sent to webhook.")
                    except Exception as wh_err:
                        print(f"  [!] Webhook notify failed: {wh_err}")

                result["notifications"].append({"message": message, "severity": severity})

            # --- recommend ---
            elif action_type == "recommend":
                text = action.get("text", "").format(
                    host=host, user=user, tier=tier, chain=chain_name, basket=basket_id[:8]
                )
                print(f"  [RECOMMEND] {text}")
                result["recommendations"].append(text)

            # --- enrich ---
            elif action_type == "enrich":
                targets = action.get("targets", [])
                print(f"  [ENRICH] Enrichment targets: {targets} (already handled by enrichment layer)")

            # --- auto_response ---
            elif action_type == "auto_response":
                action_enabled = action.get("enabled", False)
                if action_enabled and auto_response_globally_allowed:
                    source_ip = payload.get("source_ip")
                    if source_ip:
                        print(f"  [AUTO-RESPONSE] Executing IP block for {source_ip} (approved by GRC profile)")
                        try:
                            from soc_engine.response.network_block import block_ip
                            blocked = block_ip(source_ip, approved_by=f"playbook:{pb_id}")
                            result["auto_response_triggered"] = True
                            print(f"  [+] Auto-response block result: {'SUCCESS' if blocked else 'PENDING (non-admin)'}")
                        except Exception as resp_err:
                            print(f"  [!] Auto-response block error: {resp_err}")
                    else:
                        print(f"  [!] Auto-response skipped: no source IP in payload.")
                elif action_enabled and not auto_response_globally_allowed:
                    print(f"  [!] Auto-response BLOCKED by GRC profile (auto_response_allowed: false)")
                else:
                    print(f"  [SKIP] Auto-response disabled in playbook action.")

    if not result["matched_playbooks"]:
        print(f"\n[PLAYBOOK] No matching playbooks for tier={tier}, techniques={techniques}")

    return result
