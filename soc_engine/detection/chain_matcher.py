import os
import yaml
from pathlib import Path
import soc_engine.models.db as db

# Load chains from directory
def load_chains(chains_dir: str = "./soc_engine/config/chains") -> list:
    chains = []
    path = Path(chains_dir)
    if not path.exists():
        os.makedirs(path, exist_ok=True)
        
    for f in path.glob("*.yaml"):
        try:
            with open(f, "r") as fp:
                chains.append(yaml.safe_load(fp))
        except Exception as e:
            print(f"Error loading chain {f}: {e}")
            
    # Default fallback if no chain exists
    if not chains:
        chains.append({
            "chain_id": "chain_001",
            "name": "Phishing to C2",
            "stages": [
                {"stage": 1, "mitre": "T1078", "sigma_rules": ["win_system_rdp_bruteforce"]},
                {"stage": 2, "mitre": "T1059.001", "sigma_rules": ["proc_creation_win_powershell_encoded_cmd"]},
                {"stage": 3, "mitre": "T1053.005", "sigma_rules": ["proc_creation_win_scheduled_task_creation"]},
                {"stage": 4, "mitre": "T1071", "sigma_rules": ["net_connection_win_c2_potential"]}
            ],
            "time_window_minutes": 10
        })
    return chains

def evaluate_basket(basket_id: str, chains: list) -> dict:
    """
    Evaluates a basket against all loaded chains.
    Calculates confidence score based on the highest-matching chain.
    Updates the database with the results.
    """
    try:
        events = db.get_basket_events(basket_id)
    except Exception:
        events = []

    if not events:
        return {"confidence": 0, "matched_stages": [], "chain_name": None}

    highest_confidence = 0
    best_match_stages = []
    matched_chain_name = None
    matched_chain_id = None

    # Test the basket events against each chain definition
    for chain in chains:
        chain_stages = chain.get("stages", [])
        if not chain_stages:
            continue

        matched_stages_in_chain = []
        
        # Check matching for each stage in the chain
        for stage in chain_stages:
            stage_num = stage.get("stage")
            mitre_id = stage.get("mitre")
            rules_list = stage.get("sigma_rules", [])

            # Check if any event in the basket satisfies this stage
            stage_matched = False
            matching_event = None
            
            for event in events:
                raw_event_data = event.get("raw_event") or {}
                # Extract rule_id from raw event or metadata if present
                rule_id = raw_event_data.get("rule_id") or event.get("event_type")

                # Match by MITRE technique ID or by Rule ID
                if (mitre_id and event.get("mitre_technique") == mitre_id) or \
                   (rules_list and rule_id in rules_list) or \
                   (mitre_id and mitre_id in raw_event_data.get("mitre_techniques", [])):
                    stage_matched = True
                    matching_event = {
                        "event_id": str(event["event_id"]),
                        "mitre_technique": event.get("mitre_technique"),
                        "rule_id": rule_id,
                        "ingestion_time": event["ingestion_time"].isoformat() if event.get("ingestion_time") else None
                    }
                    break

            if stage_matched:
                matched_stages_in_chain.append({
                    "stage": stage_num,
                    "mitre": mitre_id,
                    "matched": True,
                    "event": matching_event
                })

        # Calculate confidence for this chain
        total_stages = len(chain_stages)
        matched_count = len(matched_stages_in_chain)
        confidence = int((matched_count / total_stages) * 100) if total_stages > 0 else 0

        # Maintain highest confidence score across chains
        if confidence > highest_confidence:
            highest_confidence = confidence
            best_match_stages = matched_stages_in_chain
            matched_chain_name = chain.get("name")
            matched_chain_id = chain.get("chain_id")

    # Update the basket in the database
    if highest_confidence > 0:
        try:
            db.update_basket_confidence(
                basket_id=basket_id,
                confidence_score=highest_confidence,
                matched_stages=best_match_stages
            )
        except Exception:
            pass

    return {
        "confidence": highest_confidence,
        "matched_stages": best_match_stages,
        "chain_name": matched_chain_name,
        "chain_id": matched_chain_id
    }
