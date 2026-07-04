"""
detection/chain_matcher.py
--------------------------
Evaluates incident baskets against YAML-defined attack chain definitions.

Key behaviours:
  - Matches basket events to chain stages by MITRE technique ID or Sigma rule ID.
  - Enforces the per-chain time_window_minutes: only events within the window
    (relative to the EARLIEST event in the basket) are eligible.
  - Returns the highest-confidence chain match across all loaded chain definitions.
  - Persists confidence and matched_stages back to PostgreSQL after each evaluation.
"""
import os
import yaml
from pathlib import Path
from datetime import datetime, timezone, timedelta

import soc_engine.models.db as db


# ------------------------------------------------------------------ #
# Chain loading                                                         #
# ------------------------------------------------------------------ #

def load_chains(chains_dir: str = "./soc_engine/config/chains") -> list:
    """
    Loads all YAML chain definitions from chains_dir.
    Falls back to a built-in Phishing → C2 definition if none exist.

    Returns:
        List of chain definition dicts.
    """
    chains = []
    path = Path(chains_dir)
    if not path.exists():
        os.makedirs(path, exist_ok=True)

    for f in path.glob("*.yaml"):
        try:
            with open(f, "r") as fp:
                chain = yaml.safe_load(fp)
                if chain and "stages" in chain:
                    chains.append(chain)
        except Exception as e:
            print(f"[!] Error loading chain {f}: {e}")

    # Built-in fallback (covers Phase 2 demo if chains/ dir is empty)
    if not chains:
        print("[!] No chain YAMLs found -- using built-in Phishing -> C2 fallback.")
        chains.append({
            "chain_id": "chain_001",
            "name": "Phishing to C2",
            "stages": [
                {"stage": 1, "mitre": "T1078",     "sigma_rules": ["win_system_rdp_bruteforce"]},
                {"stage": 2, "mitre": "T1059.001", "sigma_rules": ["proc_creation_win_powershell_encoded_cmd"]},
                {"stage": 3, "mitre": "T1053.005", "sigma_rules": ["proc_creation_win_scheduled_task_creation"]},
                {"stage": 4, "mitre": "T1071",     "sigma_rules": ["net_connection_win_c2_potential"]},
            ],
            "time_window_minutes": 10,
            "min_stages_for_alert": 2,
        })

    print(f"[*] Loaded {len(chains)} attack chain(s): {[c.get('name') for c in chains]}")
    return chains


# ------------------------------------------------------------------ #
# Time-window filtering                                                #
# ------------------------------------------------------------------ #

def _parse_event_time(event: dict) -> datetime | None:
    """
    Returns the ingestion_time of a basket event as a UTC-aware datetime.
    Falls back to event_time if ingestion_time is absent.
    Returns None if neither can be parsed.
    """
    ts = event.get("ingestion_time") or event.get("event_time")
    if ts is None:
        return None

    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            return ts.replace(tzinfo=timezone.utc)
        return ts

    if isinstance(ts, str):
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return dt
        except Exception:
            return None

    return None


def _filter_events_by_window(events: list, time_window_minutes: int) -> list:
    """
    Restricts events to those that fall within time_window_minutes of the
    EARLIEST event in the basket (i.e. the basket's first evidence).

    This is the "silent basket killer" guard from the spec:
        Use @timestamp (ingestion time) for correlation, not the endpoint clock.

    Args:
        events:               All events from the basket.
        time_window_minutes:  Chain's time_window_minutes value.

    Returns:
        Subset of events within the time window. Returns all events if
        time_window_minutes <= 0 (disabled) or timestamps cannot be parsed.
    """
    if time_window_minutes <= 0:
        return events

    parsed_times = [(_parse_event_time(e), e) for e in events]
    valid = [(t, e) for t, e in parsed_times if t is not None]

    if not valid:
        # No parseable timestamps — allow all events (fail open for live operation)
        return events

    earliest = min(t for t, _ in valid)
    cutoff = earliest + timedelta(minutes=time_window_minutes)

    windowed = [e for t, e in parsed_times if t is not None and t <= cutoff]

    # Include events without timestamps (they won't expire the window)
    no_ts = [e for t, e in parsed_times if t is None]

    return windowed + no_ts


# ------------------------------------------------------------------ #
# Basket evaluation                                                    #
# ------------------------------------------------------------------ #

def evaluate_basket(basket_id: str, chains: list) -> dict:
    """
    Evaluates a basket against all loaded chain definitions.

    For each chain:
      1. Filters basket events to the chain's time_window_minutes.
      2. Checks each stage for a matching event (by MITRE ID or Sigma rule ID).
      3. Calculates confidence = matched_stages / total_stages * 100.

    Returns the result for the highest-confidence chain found.
    Updates the database with the confidence and matched_stages.

    Args:
        basket_id: UUID string of the basket to evaluate.
        chains:    List of chain definition dicts (from load_chains).

    Returns:
        {
            "confidence":     int 0-100,
            "matched_stages": list of stage dicts,
            "chain_name":     str or None,
            "chain_id":       str or None,
        }
    """
    try:
        events = db.get_basket_events(basket_id)
    except Exception:
        events = []

    if not events:
        return {"confidence": 0, "matched_stages": [], "chain_name": None, "chain_id": None}

    highest_confidence = 0
    best_match_stages  = []
    matched_chain_name = None
    matched_chain_id   = None

    for chain in chains:
        chain_stages        = chain.get("stages", [])
        time_window_minutes = chain.get("time_window_minutes", 10)

        if not chain_stages:
            continue

        # --- Apply time-window filter ---
        windowed_events = _filter_events_by_window(events, time_window_minutes)
        if not windowed_events:
            continue

        matched_stages_in_chain = []

        for stage in chain_stages:
            stage_num  = stage.get("stage")
            mitre_id   = stage.get("mitre")
            rules_list = stage.get("sigma_rules", [])

            stage_matched  = False
            matching_event = None

            for event in windowed_events:
                raw_event_data = event.get("raw_event") or {}
                rule_id = raw_event_data.get("rule_id") or event.get("event_type")

                # Match by MITRE technique ID or Sigma rule ID
                if (
                    (mitre_id   and event.get("mitre_technique") == mitre_id) or
                    (rules_list and rule_id in rules_list) or
                    (mitre_id   and mitre_id in raw_event_data.get("mitre_techniques", []))
                ):
                    stage_matched = True
                    matching_event = {
                        "event_id":       str(event["event_id"]),
                        "mitre_technique": event.get("mitre_technique"),
                        "rule_id":        rule_id,
                        "ingestion_time": (
                            event["ingestion_time"].isoformat()
                            if event.get("ingestion_time") else None
                        ),
                    }
                    break

            if stage_matched:
                matched_stages_in_chain.append({
                    "stage":   stage_num,
                    "mitre":   mitre_id,
                    "matched": True,
                    "event":   matching_event,
                })

        total_stages = len(chain_stages)
        matched_count = len(matched_stages_in_chain)
        confidence = int((matched_count / total_stages) * 100) if total_stages > 0 else 0

        if confidence > highest_confidence:
            highest_confidence = confidence
            best_match_stages  = matched_stages_in_chain
            matched_chain_name = chain.get("name")
            matched_chain_id   = chain.get("chain_id")

    # Persist results back to PostgreSQL
    if highest_confidence > 0:
        try:
            db.update_basket_confidence(
                basket_id=basket_id,
                confidence_score=highest_confidence,
                matched_stages=best_match_stages,
            )
        except Exception:
            pass

    return {
        "confidence":     highest_confidence,
        "matched_stages": best_match_stages,
        "chain_name":     matched_chain_name,
        "chain_id":       matched_chain_id,
    }
