"""
main.py
-------
LogXPro SOC Correlation Engine — Entry Point

Usage:
    python -m soc_engine.main                # Live mode (connects to ES/PG/Redis)
    python -m soc_engine.main --simulate     # Phishing → C2 simulation
    python -m soc_engine.main --simulate --chain lateral   # Lateral movement simulation
    python -m soc_engine.main --simulate --chain ransomware  # Ransomware simulation
"""
import os
import sys
import time
import argparse
from datetime import datetime, timezone, timedelta
from elasticsearch import Elasticsearch
import psycopg2
import yaml

from soc_engine.config.settings import settings
from soc_engine.detection.sigma_matcher import SigmaMatcher
from soc_engine.detection.chain_matcher import load_chains, evaluate_basket
from soc_engine.detection.tiering import (
    should_fire_alert,
    format_alert_banner,
    build_alert_payload,
    is_duplicate,
)
import soc_engine.detection.basket_manager as basket_manager
import soc_engine.models.db as db


class SOCEngine:
    def __init__(self, simulate: bool = False):
        self.simulate = simulate
        self.sigma_matcher = SigmaMatcher()
        self.chains = load_chains()
        self.es_client = None
        self.grc_profile = {}

        self.load_grc_profile()

        # Phase 6: Pre-load playbooks at startup
        from soc_engine.playbooks.playbook_runner import load_playbooks
        load_playbooks()

        if not self.simulate:
            self.init_connections()

    def _redact_pii_fields(self, event_dict: dict) -> dict:
        """Redacts PII fields from the log event prior to database/ES storage."""
        import copy
        copied = copy.deepcopy(event_dict)
        
        # Redact user details
        if "user" in copied and isinstance(copied["user"], dict):
            if "name" in copied["user"]:
                copied["user"]["name"] = "[REDACTED_USER]"
        if "user_name" in copied:
            copied["user_name"] = "[REDACTED_USER]"
        if "TargetUserName" in copied:
            copied["TargetUserName"] = "[REDACTED_USER]"
            
        # Redact source/destination IPs
        if "source" in copied and isinstance(copied["source"], dict):
            if "ip" in copied["source"]:
                copied["source"]["ip"] = "[REDACTED_IP]"
        if "destination" in copied and isinstance(copied["destination"], dict):
            if "ip" in copied["destination"]:
                copied["destination"]["ip"] = "[REDACTED_IP]"
        if "source_ip" in copied:
            copied["source_ip"] = "[REDACTED_IP]"
        if "dest_ip" in copied:
            copied["dest_ip"] = "[REDACTED_IP]"
        if "IpAddress" in copied:
            copied["IpAddress"] = "[REDACTED_IP]"
            
        return copied

    # ------------------------------------------------------------------ #
    # Startup                                                               #
    # ------------------------------------------------------------------ #

    def load_grc_profile(self):
        """Loads the active GRC profile from YAML."""
        profile_path = os.path.join(
            settings.GRC_PROFILE_DIR, f"{settings.ACTIVE_GRC_PROFILE}.yaml"
        )
        try:
            with open(profile_path, "r") as f:
                self.grc_profile = yaml.safe_load(f)
            print(
                f"[*] GRC Profile: {self.grc_profile.get('client')} "
                f"(Industry: {self.grc_profile.get('industry', 'N/A')})"
            )
        except Exception as e:
            print(f"[!] Could not load GRC profile at {profile_path}: {e}")
            self.grc_profile = {
                "client": "Default",
                "enabled_rule_groups": ["endpoint", "network", "ad"],
                "auto_response_allowed": False,
            }

    def init_connections(self):
        """Attempts to connect to ES, PostgreSQL and Redis."""
        print("[*] Initialising connections...")

        # Elasticsearch
        try:
            self.es_client = Elasticsearch(
                settings.ES_HOST, request_timeout=2.0, max_retries=0
            )
            if not self.es_client.ping():
                print("[!] Elasticsearch not reachable → switching to SIMULATE mode.")
                self.simulate = True
            else:
                print("[+] Elasticsearch connected.")
        except Exception as e:
            print(f"[!] ES error: {e} → switching to SIMULATE mode.")
            self.simulate = True

        # PostgreSQL
        try:
            conn = psycopg2.connect(
                host=settings.DB_HOST,
                port=settings.DB_PORT,
                database=settings.DB_NAME,
                user=settings.DB_USER,
                password=settings.DB_PASSWORD,
                connect_timeout=2,
            )
            conn.close()
            print("[+] PostgreSQL connected.")
        except Exception as e:
            print(f"[!] PostgreSQL error: {e} → switching to SIMULATE mode.")
            self.simulate = True

        # Redis
        try:
            basket_manager.redis_client.ping()
            print("[+] Redis connected.")
        except Exception as e:
            print(f"[!] Redis error: {e} → switching to SIMULATE mode.")
            self.simulate = True

        # Phase 6: Apply Elasticsearch ILM policy (retention from GRC profile)
        if self.es_client and not self.simulate:
            try:
                from soc_engine.infra.es_ilm import apply_ilm_policy
                apply_ilm_policy(self.es_client, self.grc_profile)
            except Exception as ilm_err:
                print(f"[!] ILM policy apply failed (non-fatal): {ilm_err}")

    # ------------------------------------------------------------------ #
    # Run dispatch                                                          #
    # ------------------------------------------------------------------ #

    def run(self, sim_chain: str = "phishing"):
        print("=" * 60)
        print("      LOGXPRO AUTONOMOUS SOC CORRELATION ENGINE v2.0      ")
        print("=" * 60)
        if self.simulate:
            self.run_simulation(sim_chain)
        else:
            self.run_polling_loop()

    # ------------------------------------------------------------------ #
    # Live mode                                                             #
    # ------------------------------------------------------------------ #

    def run_polling_loop(self):
        """Polls Elasticsearch for new logs every POLL_INTERVAL seconds."""
        from soc_engine.ingestion.es_reader import ESReader

        print("[*] Starting live ES polling loop...")
        reader = ESReader(self.es_client)
        last_polled = datetime.now(timezone.utc) - timedelta(minutes=1)

        while True:
            try:
                # Expire old open baskets
                try:
                    db.expire_old_open_baskets(settings.BASKET_EXPIRY_MINUTES)
                except Exception as ex:
                    print(f"[!] Error running open basket cleanup: {ex}")
                now = datetime.now(timezone.utc)
                events = reader.get_events_with_scroll(start_time=last_polled, end_time=now)

                if events:
                    print(f"[*] {len(events)} new events received. Processing...")
                    for event in events:
                        self.process_log(event)

                last_polled = now
            except KeyboardInterrupt:
                print("\n[*] Engine stopped by user.")
                break
            except Exception as e:
                print(f"[!] Polling error: {e}")

            time.sleep(settings.POLL_INTERVAL)

    def process_log(self, event: dict):
        """Processes a single log event: Anomaly detection, Sigma matching → basket → chain eval → alert."""
        # 1. Login Anomaly check (Phase 5)
        event_code = event.get("event", {}).get("code")
        if event_code in [4624, 4672] and not self.simulate:
            user_name = event.get("user", {}).get("name")
            source_ip = event.get("source", {}).get("ip")
            if user_name and source_ip:
                try:
                    conn = db.get_db_connection()
                    try:
                        ts_str = event.get("@timestamp")
                        from datetime import datetime, timezone
                        if ts_str:
                            try:
                                login_time = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                            except Exception:
                                login_time = datetime.now(timezone.utc)
                        else:
                            login_time = datetime.now(timezone.utc)
                            
                        source_country = event.get("source", {}).get("country", "US") or "US"
                        
                        from soc_engine.anomaly.baseline_checker import check_anomaly, update_baseline
                        anomalies = check_anomaly(conn, user_name, source_ip, source_country, login_time)
                        update_baseline(conn, user_name, source_ip, source_country, login_time.hour)
                        
                        for anomaly in anomalies:
                            print(f"\n[!] ANOMALY DETECTED: {anomaly['description']} (Confidence: {anomaly['confidence']}%)")
                            anomaly_rule = {
                                "id": f"win_login_anomaly_{anomaly['type']}",
                                "title": f"Login Anomaly: {anomaly['type'].replace('_', ' ').title()}",
                                "level": "medium" if anomaly["confidence"] >= 40 else "low",
                                "mitre_techniques": ["T1078"],
                                "group": "active_directory"
                            }
                            self._process_rule_match(event, anomaly_rule)
                    finally:
                        conn.close()
                except Exception as db_err:
                    print(f"[!] Error checking login anomaly: {db_err}")

        # 2. Sigma Rule matching
        matches = self.sigma_matcher.match_event(event)
        for rule in matches:
            self._process_rule_match(event, rule)

    def _process_rule_match(self, event: dict, rule: dict):
        """Processes a specific rule match (Sigma or Anomaly) through the basket and alert pipeline."""
        rule_id = rule["id"]
        host_name = event.get("host", {}).get("name", "UNKNOWN_HOST")
        user_name = event.get("user", {}).get("name")

        # GRC suppression check
        rule_group = rule.get("group")
        disabled_groups = self.grc_profile.get("disabled_rule_groups", [])
        rule_tags = [t.lower() for t in rule.get("tags", [])]
        is_suppressed = False
        if rule_group and rule_group in disabled_groups:
            is_suppressed = True
        else:
            for dg in disabled_groups:
                if dg.lower() in rule_tags or f"attack.{dg.lower()}" in rule_tags:
                    is_suppressed = True
                    rule_group = dg
                    break

        if is_suppressed:
            print(f"[-] GRC suppressed rule {rule_id} (group '{rule_group}' disabled for this client)")
            return

        # Alert suppression table check
        if not self.simulate:
            try:
                if db.is_alert_suppressed(host_name, user_name, rule_id):
                    print(f"[-] Suppressed: {rule_id} on {host_name}/{user_name}")
                    return
            except Exception as se_err:
                print(f"[!] Error checking alert suppression: {se_err}")

        print(
            f"\n[!] RULE HIT: '{rule['title']}' "
            f"(Level: {rule['level'].upper()}) | "
            f"Host: {host_name} | User: {user_name or 'N/A'}"
        )

        # Redact raw_event for storage if PII redaction is enabled in GRC profile
        store_event = event
        if self.grc_profile.get("pii_redaction", False):
            store_event = self._redact_pii_fields(event)

        # Basket management
        source_ip = event.get("source", {}).get("ip")
        basket, is_new = basket_manager.find_or_create_basket(
            host_name, user_name, source_ip
        )
        basket_id = str(basket["basket_id"])

        mitre_id = rule["mitre_techniques"][0] if rule["mitre_techniques"] else None
        basket_manager.add_event(
            basket_id=basket_id,
            event_type=rule["title"],
            raw_event={**store_event, "rule_id": rule_id},
            mitre_technique=mitre_id
        )
        print(f"    [+] Event → basket {basket_id[:8]}... (new={is_new})")

        # Chain evaluation
        eval_res = evaluate_basket(basket_id, self.chains)

        if eval_res["confidence"] > 0:
            print(
                f"    [>>>] Chain: '{eval_res['chain_name']}' | "
                f"Confidence: {eval_res['confidence']}% | "
                f"Stages: {len(eval_res['matched_stages'])}"
            )

        # Determine the best chain for tiering
        best_chain = self._find_chain(eval_res.get("chain_id"))
        alert_type, tier = should_fire_alert(basket, rule, best_chain or {}, eval_res)

        if alert_type:
            # Phase 3: Run enrichment for Tier 2 or above (Medium, High, Critical)
            enrichment_data = None
            if tier in ["medium", "high", "critical"]:
                from soc_engine.enrichment import enrich_basket
                try:
                    conn = db.get_db_connection()
                    try:
                        enrichment_data = enrich_basket(conn, basket_id)
                    finally:
                        conn.close()
                except Exception as e:
                    print(f"[!] Error running enrichment orchestrator: {e}")

            banner = format_alert_banner(alert_type, tier, basket, eval_res)
            print(banner)

            payload = build_alert_payload(basket, eval_res, alert_type, tier, rule)
            if enrichment_data:
                payload["enrichment"] = enrichment_data

            # Phase 4: Run AI Narrative Generator
            if tier in ["medium", "high", "critical"]:
                from soc_engine.ai import generate_incident_narrative
                try:
                    narrative = generate_incident_narrative(
                        basket,
                        enrichment_data or {},
                        best_chain or {}
                    )
                    payload["ai_narrative"] = narrative
                except Exception as e:
                    print(f"[!] Error running AI narrator: {e}")

            self._handle_alert(payload)

    def _handle_alert(self, payload: dict):
        """
        Alert dispatch: prints structured JSON, indexes to Elasticsearch 'soc-alerts',
        forwards high/critical alerts to TheHive, runs playbooks, and writes audit log.
        """
        import json
        print(f"    [ALERT PAYLOAD] {json.dumps(payload, indent=2, default=str)}")

        # Phase 4: Index to Elasticsearch index 'soc-alerts'
        if not self.simulate and self.es_client:
            try:
                resp = self.es_client.index(index="soc-alerts", document=payload)
                print(f"    [+] Alert successfully indexed to Elasticsearch 'soc-alerts' (ID: {resp.get('_id')})")
            except Exception as e:
                print(f"[!] Failed to index alert to Elasticsearch 'soc-alerts': {e}")

        # Phase 5: Forward High and Critical alerts to TheHive SOAR
        if payload.get("tier") in ["high", "critical"]:
            from soc_engine.response.thehive_client import create_case
            try:
                print(f"[*] Forwarding {payload.get('tier').upper()} alert to TheHive...")
                create_case(payload)
            except Exception as e:
                print(f"[!] Failed to forward alert to TheHive: {e}")

        # Phase 6: Run playbook engine
        playbook_result = {}
        try:
            from soc_engine.playbooks.playbook_runner import run_playbook
            playbook_result = run_playbook(payload, self.grc_profile)
            payload["playbook_result"] = playbook_result
        except Exception as pb_err:
            print(f"[!] Playbook runner error: {pb_err}")

        # Phase 6: Run YARA scan on basket event command lines
        try:
            from soc_engine.detection.yara_scanner import scan_basket_events
            basket_events = payload.get("events") or []
            # If events are not embedded, simulate by scanning matched stage descriptions
            if not basket_events:
                # Create mock events from matched stages for simulation
                basket_events = [
                    {"raw_event": stage.get("event", {})} for stage in payload.get("matched_stages", [])
                ]
            yara_matches = scan_basket_events(basket_events)
            if yara_matches:
                payload["yara_matches"] = yara_matches
                print(f"    [YARA] {len(yara_matches)} rule(s) matched in basket events: {[m['rule'] for m in yara_matches]}")
        except Exception as yara_err:
            print(f"[!] YARA scan error (non-fatal): {yara_err}")

        # Phase 6: Write to audit log (live mode only)
        if not self.simulate:
            try:
                conn = db.get_db_connection()
                try:
                    from soc_engine.models.audit_log import log_alert_fired, log_playbook_fired
                    log_alert_fired(
                        conn,
                        basket_id=payload.get("basket_id"),
                        rule_id=(payload.get("triggering_rule") or {}).get("id"),
                        tier=payload.get("tier"),
                        chain_name=payload.get("chain_name"),
                        confidence=payload.get("confidence_score", 0)
                    )
                    if playbook_result.get("matched_playbooks"):
                        log_playbook_fired(
                            conn,
                            basket_id=payload.get("basket_id"),
                            playbook_id=",".join(playbook_result["matched_playbooks"]),
                            tier=payload.get("tier"),
                            actions_taken=playbook_result.get("notifications", []),
                            auto_response=playbook_result.get("auto_response_triggered", False)
                        )
                finally:
                    conn.close()
            except Exception as audit_err:
                print(f"[!] Audit log write error (non-fatal): {audit_err}")

    def _find_chain(self, chain_id: str | None) -> dict | None:
        if not chain_id:
            return self.chains[0] if self.chains else None
        for c in self.chains:
            if c.get("chain_id") == chain_id:
                return c
        return self.chains[0] if self.chains else None

    # ------------------------------------------------------------------ #
    # Simulation mode                                                       #
    # ------------------------------------------------------------------ #

    def run_simulation(self, sim_chain: str = "phishing"):
        """
        Runs one of three pre-built attack simulations without requiring
        any running infrastructure (ES / PG / Redis).

        Available simulations:
            phishing    → RDP brute force → PowerShell → Scheduled Task → C2
            lateral     → Privilege escalation → Mimikatz → WMI lateral movement → Net enum
            ransomware  → Defender disable → Shadow copy delete → WMIC → Encoding payload
        """
        sims = {
            "phishing":   self._sim_phishing_c2,
            "lateral":    self._sim_lateral_movement,
            "ransomware": self._sim_ransomware,
        }

        sim_fn = sims.get(sim_chain, self._sim_phishing_c2)
        sim_events = sim_fn()

        chain_target = self._pick_sim_chain(sim_chain)

        print(f"\n[*] Running Simulation: '{sim_chain}' ({len(sim_events)} events)")
        print(f"[*] Target Chain: '{chain_target.get('name', 'N/A')}'")
        print("=" * 60)

        # In-memory mock basket
        mock_basket = {
            "basket_id": f"SIM-BASKET-{sim_chain.upper()}",
            "host_name": "DESKTOP-VICTIM",
            "user_name": "Administrator",
            "source_ip": "192.168.1.50",
            "status": "open",
            "confidence_score": 0,
            "matched_stages": [],
        }
        mock_events_store = []

        for i, step in enumerate(sim_events, start=1):
            desc = step["description"]
            log = step["log"]
            expected_rule_id = step["rule_id"]

            print(f"\n>>> [{i}/{len(sim_events)}] {desc}")
            time.sleep(1.5)

            # Check for logon anomaly in simulation (Phase 5)
            sim_rules_to_eval = []
            event_code = log.get("event", {}).get("code")
            if event_code in [4624, 4672]:
                anomaly_rule = {
                    "id": "win_login_anomaly_first_seen_ip",
                    "title": "Login Anomaly: First Seen Ip",
                    "level": "medium",
                    "mitre_techniques": ["T1078"],
                    "group": "active_directory"
                }
                print(f"    [!] ANOMALY DETECTED: First login from {log.get('source', {}).get('ip')} for user {log.get('user', {}).get('name')} (Confidence: 30%)")
                sim_rules_to_eval.append(anomaly_rule)

            matches = self.sigma_matcher.match_event(log)
            sim_rules_to_eval.extend(matches)

            if not sim_rules_to_eval:
                print(f"    [-] No Sigma rule matched for this event.")
                continue

            # Redact raw_event in simulation if GRC profile specifies it (Phase 5)
            store_log = log
            if self.grc_profile.get("pii_redaction", False):
                store_log = self._redact_pii_fields(log)

            for rule in sim_rules_to_eval:
                rule_id = rule["id"]
                print(f"    [!] RULE: '{rule['title']}' (Level: {rule['level'].upper()})")

                # Add to mock store
                evt_record = {
                    "event_id": f"SIM-EVT-{i:03d}",
                    "basket_id": mock_basket["basket_id"],
                    "event_type": rule["title"],
                    "raw_event": {**store_log, "rule_id": rule_id},
                    "mitre_technique": step["mitre"] if rule_id != "win_login_anomaly_first_seen_ip" else "T1078",
                    "ingestion_time": datetime.now(timezone.utc),
                }
                mock_events_store.append(evt_record)
                print(f"    [+] Event added to mock basket ({len(mock_events_store)} events total)")

                # Evaluate basket against chain
                chain_stages = chain_target.get("stages", [])
                matched_stages = []

                for stage in chain_stages:
                    stage_num = stage.get("stage")
                    mitre_id = stage.get("mitre")
                    rules_list = stage.get("sigma_rules", [])

                    for ev in mock_events_store:
                        ev_mitre = ev.get("mitre_technique", "")
                        raw_evt = ev.get("raw_event") or {}
                        ev_rule = raw_evt.get("rule_id") or ev.get("event_type", "")
                        if ev_mitre == mitre_id or ev_rule in rules_list:
                            matched_stages.append({
                                "stage": stage_num,
                                "mitre": mitre_id,
                                "matched": True,
                                "event": {
                                    "event_id": ev["event_id"],
                                    "mitre_technique": ev_mitre,
                                    "rule_id": ev_rule,
                                }
                            })
                            break

                total_stages = len(chain_stages)
                confidence = int((len(matched_stages) / total_stages) * 100) if total_stages else 0

                mock_basket["matched_stages"] = matched_stages
                mock_basket["confidence_score"] = confidence

                eval_res = {
                    "confidence": confidence,
                    "matched_stages": matched_stages,
                    "chain_name": chain_target.get("name"),
                    "chain_id": chain_target.get("chain_id"),
                }

                min_stages = chain_target.get("min_stages_for_alert", 2)

                print(
                    f"    [>>>] Chain: '{eval_res['chain_name']}' | "
                    f"Confidence: {confidence}% | "
                    f"Stages Matched: {len(matched_stages)}/{total_stages}"
                )

                alert_type = None
                tier = None
                if len(matched_stages) >= min_stages:
                    from soc_engine.detection.tiering import score_to_tier
                    tier = score_to_tier(confidence)
                    if tier:
                        alert_type = "tier_chain"
                elif rule["level"] == "critical":
                    alert_type = "tier0_instant"
                    tier = "critical"

                if alert_type:
                    from soc_engine.detection.tiering import format_alert_banner, build_alert_payload
                    banner = format_alert_banner(alert_type, tier, mock_basket, eval_res)
                    print(banner)

                    payload = build_alert_payload(mock_basket, eval_res, alert_type, tier, rule)

                    # Phase 3: Run enrichment for Tier 2 or above (or instant critical)
                    enrichment_data = None
                    if tier in ["medium", "high", "critical"]:
                        from soc_engine.enrichment import enrich_basket
                        # In simulation, we don't have real pg_conn, pass None.
                        # Also, mock_events_store holds all the events for the mock basket.
                        enrichment_data = enrich_basket(None, mock_basket["basket_id"], mock_events_store)
                        payload["enrichment"] = enrichment_data

                    # Phase 4: Run AI Narrative Generator in simulation
                    if tier in ["medium", "high", "critical"]:
                        from soc_engine.ai import generate_incident_narrative
                        try:
                            narrative = generate_incident_narrative(
                                mock_basket,
                                enrichment_data or {},
                                chain_target
                            )
                            payload["ai_narrative"] = narrative
                        except Exception as e:
                            print(f"[!] Error running AI narrator in simulation: {e}")

                    self._handle_alert(payload)

        print("\n" + "=" * 60)
        print("[+] Simulation complete.")
        print(
            f"[+] Final basket confidence: {mock_basket['confidence_score']}% "
            f"({len(mock_basket['matched_stages'])} of "
            f"{len(chain_target.get('stages', []))} stages matched)"
        )
        print("=" * 60)

    def _pick_sim_chain(self, sim_chain: str) -> dict:
        """Returns the chain definition that best matches the simulation scenario."""
        chain_name_map = {
            "phishing":   "chain_001",
            "lateral":    "chain_002",
            "ransomware": "chain_003",
        }
        target_id = chain_name_map.get(sim_chain, "chain_001")
        for c in self.chains:
            if c.get("chain_id") == target_id:
                return c
        return self.chains[0] if self.chains else {}

    # ------------------------------------------------------------------ #
    # Simulation event generators                                           #
    # ------------------------------------------------------------------ #

    def _sim_phishing_c2(self) -> list:
        """Phishing → C2 four-stage simulation events."""
        now = datetime.now(timezone.utc)
        return [
            {
                "description": "Stage 1 — RDP Brute Force Login Failure (T1078)",
                "mitre": "T1078",
                "rule_id": "win_system_rdp_bruteforce",
                "log": {
                    "@timestamp": now.isoformat(),
                    "host": {"name": "DESKTOP-VICTIM"},
                    "user": {"name": "Administrator"},
                    "event": {"code": 4625},
                    "source": {"ip": "192.168.1.50"},
                },
            },
            {
                "description": "Stage 2 — PowerShell Encoded Command Execution (T1059.001)",
                "mitre": "T1059.001",
                "rule_id": "proc_creation_win_powershell_encoded_cmd",
                "log": {
                    "@timestamp": (now + timedelta(seconds=3)).isoformat(),
                    "host": {"name": "DESKTOP-VICTIM"},
                    "user": {"name": "Administrator"},
                    "event": {"code": 1},
                    "process": {
                        "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        "command_line": "powershell.exe -enc SQBFAFMAIAAoAE4A...",
                        "entity_id": "{a398-0001}",
                    },
                },
            },
            {
                "description": "Stage 3 — Scheduled Task Persistence (T1053.005)",
                "mitre": "T1053.005",
                "rule_id": "proc_creation_win_scheduled_task_creation",
                "log": {
                    "@timestamp": (now + timedelta(seconds=6)).isoformat(),
                    "host": {"name": "DESKTOP-VICTIM"},
                    "user": {"name": "Administrator"},
                    "event": {"code": 1},
                    "process": {
                        "executable": "C:\\Windows\\System32\\schtasks.exe",
                        "command_line": "schtasks /create /tn \"WindowsUpdate\" /tr "
                                        "\"powershell.exe -WindowStyle Hidden\" /sc minute /mo 30",
                    },
                },
            },
            {
                "description": "Stage 4 — Outbound C2 Beacon to 203.0.113.99:443 (T1071)",
                "mitre": "T1071",
                "rule_id": "net_connection_win_c2_potential",
                "log": {
                    "@timestamp": (now + timedelta(seconds=9)).isoformat(),
                    "host": {"name": "DESKTOP-VICTIM"},
                    "user": {"name": "Administrator"},
                    "event": {"code": 3},
                    "destination": {"ip": "203.0.113.99", "port": 443},
                    "source": {"ip": "192.168.1.100"},
                },
            },
        ]

    def _sim_lateral_movement(self) -> list:
        """Credential Dumping → Lateral Movement simulation events."""
        now = datetime.now(timezone.utc)
        return [
            {
                "description": "Stage 1 — Special Privilege Logon (T1078.002)",
                "mitre": "T1078.002",
                "rule_id": "win_special_privilege_logon",
                "log": {
                    "@timestamp": now.isoformat(),
                    "host": {"name": "DESKTOP-VICTIM"},
                    "user": {"name": "svc_admin"},
                    "event": {"code": 4672},
                    "source": {"ip": "10.0.0.5"},
                },
            },
            {
                "description": "Stage 2 — Mimikatz Credential Dump (T1003.001) [CRITICAL]",
                "mitre": "T1003.001",
                "rule_id": "proc_creation_win_mimikatz",
                "log": {
                    "@timestamp": (now + timedelta(seconds=5)).isoformat(),
                    "host": {"name": "DESKTOP-VICTIM"},
                    "user": {"name": "svc_admin"},
                    "event": {"code": 1},
                    "process": {
                        "executable": "C:\\Temp\\mimikatz.exe",
                        "command_line": "mimikatz.exe sekurlsa::logonpasswords",
                    },
                    "Hashes": "SHA256=4b6842bf8276eac8677250a98956ff34d5678ab3e456cde90f123456789abcde",
                },
            },
            {
                "description": "Stage 3 — WMI Spawning cmd.exe for Lateral Movement (T1021.002)",
                "mitre": "T1021.002",
                "rule_id": "proc_creation_win_wmi_spawns_process",
                "log": {
                    "@timestamp": (now + timedelta(seconds=10)).isoformat(),
                    "host": {"name": "DESKTOP-VICTIM"},
                    "user": {"name": "svc_admin"},
                    "event": {"code": 1},
                    "process": {
                        "parent": {"executable": "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe"},
                        "executable": "C:\\Windows\\System32\\cmd.exe",
                        "command_line": "cmd.exe /c whoami",
                    },
                },
            },
            {
                "description": "Stage 4 — Domain Enumeration via net.exe (T1087.002)",
                "mitre": "T1087.002",
                "rule_id": "proc_creation_win_net_user_enum",
                "log": {
                    "@timestamp": (now + timedelta(seconds=15)).isoformat(),
                    "host": {"name": "DESKTOP-VICTIM"},
                    "user": {"name": "svc_admin"},
                    "event": {"code": 1},
                    "process": {
                        "executable": "C:\\Windows\\System32\\net.exe",
                        "command_line": "net.exe user /domain",
                    },
                },
            },
        ]

    def _sim_ransomware(self) -> list:
        """Ransomware Pre-Deployment simulation events."""
        now = datetime.now(timezone.utc)
        return [
            {
                "description": "Stage 1 — Disable Windows Defender (T1562.001)",
                "mitre": "T1562.001",
                "rule_id": "proc_creation_win_defender_disable",
                "log": {
                    "@timestamp": now.isoformat(),
                    "host": {"name": "FILESERVER-01"},
                    "user": {"name": "Administrator"},
                    "event": {"code": 1},
                    "process": {
                        "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        "command_line": "Set-MpPreference -DisableRealtimeMonitoring $true",
                    },
                },
            },
            {
                "description": "Stage 2 — Stop VSS Service via sc.exe (T1562.001)",
                "mitre": "T1562.001",
                "rule_id": "proc_creation_win_sc_stop_security",
                "log": {
                    "@timestamp": (now + timedelta(seconds=4)).isoformat(),
                    "host": {"name": "FILESERVER-01"},
                    "user": {"name": "Administrator"},
                    "event": {"code": 1},
                    "process": {
                        "executable": "C:\\Windows\\System32\\sc.exe",
                        "command_line": "sc.exe stop VSS",
                    },
                },
            },
            {
                "description": "Stage 3 — Delete Shadow Copies via vssadmin [CRITICAL] (T1490)",
                "mitre": "T1490",
                "rule_id": "proc_creation_win_vssadmin_delete_shadows",
                "log": {
                    "@timestamp": (now + timedelta(seconds=8)).isoformat(),
                    "host": {"name": "FILESERVER-01"},
                    "user": {"name": "Administrator"},
                    "event": {"code": 1},
                    "process": {
                        "executable": "C:\\Windows\\System32\\vssadmin.exe",
                        "command_line": "vssadmin.exe delete shadows /all /quiet",
                    },
                },
            },
            {
                "description": "Stage 4 — PowerShell Ransom Payload Dropper (T1059.001)",
                "mitre": "T1059.001",
                "rule_id": "proc_creation_win_powershell_encoded_cmd",
                "log": {
                    "@timestamp": (now + timedelta(seconds=12)).isoformat(),
                    "host": {"name": "FILESERVER-01"},
                    "user": {"name": "Administrator"},
                    "event": {"code": 1},
                    "process": {
                        "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        "command_line": "powershell.exe -enc UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgAC0ARgBpAGwAZQBQAGEAdABoACAAQwA6AFwAUABhAHkAbABvAGEAZAAuAGUAeABlAA==",
                    },
                },
            },
        ]


# ------------------------------------------------------------------ #
# Entry point                                                           #
# ------------------------------------------------------------------ #

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LogXPro SOC Correlation Engine")
    parser.add_argument(
        "--simulate", "-s",
        action="store_true",
        help="Run in simulation mode (no ES/PG/Redis required)",
    )
    parser.add_argument(
        "--chain", "-c",
        choices=["phishing", "lateral", "ransomware"],
        default="phishing",
        help="Which attack chain to simulate (default: phishing)",
    )
    args = parser.parse_args()

    engine = SOCEngine(simulate=args.simulate)
    engine.run(sim_chain=args.chain)
