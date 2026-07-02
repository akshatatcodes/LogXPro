import os
import yaml
from pathlib import Path

class SigmaMatcher:
    def __init__(self, rules_dir: str = "./soc_engine/config/rules"):
        self.rules_dir = Path(rules_dir)
        self.rules = []
        self.load_rules()

    def load_rules(self):
        """
        Loads and parses all Sigma YAML rules from the rules directory.
        """
        if not self.rules_dir.exists():
            self.rules_dir.mkdir(parents=True, exist_ok=True)
            self._create_default_rules()

        for f in self.rules_dir.glob("*.yml"):
            try:
                with open(f, "r", encoding="utf-8") as fp:
                    rule_content = yaml.safe_load(fp)
                    if rule_content and "detection" in rule_content:
                        self.rules.append({
                            "file_path": str(f),
                            "id": rule_content.get("id"),
                            "title": rule_content.get("title", "Unnamed Rule"),
                            "level": rule_content.get("level", "medium"),
                            "detection": rule_content["detection"],
                            "logsource": rule_content.get("logsource", {}),
                            "mitre_techniques": self._extract_mitre_tags(rule_content.get("tags", []))
                        })
            except Exception as e:
                print(f"Error loading Sigma rule {f}: {e}")
        
        print(f"Loaded {len(self.rules)} Sigma rules successfully.")

    def _extract_mitre_tags(self, tags: list) -> list:
        """
        Extracts MITRE Technique IDs (e.g. t1059.001) from rule tags.
        """
        mitre_tags = []
        if tags:
            for tag in tags:
                tag_lower = tag.lower()
                if tag_lower.startswith("attack.t"):
                    tech_id = tag_lower.replace("attack.", "").upper()
                    mitre_tags.append(tech_id)
        return mitre_tags

    def _create_default_rules(self):
        """
        Generates standard Sigma rules for testing.
        """
        rules = {
            "win_system_rdp_bruteforce.yml": """
title: RDP Logon Bruteforce
id: win_system_rdp_bruteforce
description: Detects RDP logon failure patterns indicating brute force
logsource:
    product: windows
    service: security
detection:
    selection:
        event.code: 4625
    condition: selection
tags:
    - attack.t1078
level: medium
""",
            "proc_creation_win_powershell_encoded_cmd.yml": """
title: PowerShell Encoded Command Execution
id: proc_creation_win_powershell_encoded_cmd
description: Detects PowerShell command line with encoded argument
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        event.code: 1
        process.command_line|contains:
            - "-encodedcommand"
            - "-enc"
            - "-e "
    condition: selection
tags:
    - attack.t1059.001
level: high
""",
            "proc_creation_win_scheduled_task_creation.yml": """
title: Scheduled Task Creation
id: proc_creation_win_scheduled_task_creation
description: Detects scheduled task creation for persistence
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        event.code: 1
        process.command_line|contains:
            - "schtasks"
            - "/create"
    condition: selection
tags:
    - attack.t1053.005
level: medium
""",
            "net_connection_win_c2_potential.yml": """
title: Outbound Connection to Potential C2
id: net_connection_win_c2_potential
description: Detects outbound network connection to suspicious IP ranges
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        event.code: 3
        destination.ip:
            - "8.8.8.8"
            - "1.1.1.1"
            - "5.5.5.5"
    condition: selection
tags:
    - attack.t1071
level: high
"""
        }
        for name, content in rules.items():
            with open(self.rules_dir / name, "w", encoding="utf-8") as f:
                f.write(content.strip())

    def match_event(self, event: dict) -> list:
        """
        Evaluates a log event against all loaded Sigma rules.
        Returns a list of matching rules.
        """
        matched_rules = []
        for rule in self.rules:
            if self._evaluate_rule(event, rule):
                matched_rules.append(rule)
        return matched_rules

    def _evaluate_rule(self, event: dict, rule: dict) -> bool:
        """
        Evaluates an event against a single rule.
        Supports selection and modifiers like |contains.
        """
        detection = rule["detection"]
        selection = detection.get("selection")
        if not selection:
            return False

        flat_event = self._flatten_dict(event)

        for key_query, target_values in selection.items():
            if "|" in key_query:
                field_name, modifier = key_query.split("|", 1)
            else:
                field_name, modifier = key_query, None

            event_val = flat_event.get(field_name)
            if event_val is None:
                return False

            if not isinstance(target_values, list):
                target_list = [target_values]
            else:
                target_list = target_values

            event_val_str = str(event_val).lower()
            
            item_matched = False
            for target_val in target_list:
                target_val_str = str(target_val).lower()
                
                if modifier == "contains":
                    if target_val_str in event_val_str:
                        item_matched = True
                        break
                elif modifier == "startswith":
                    if event_val_str.startswith(target_val_str):
                        item_matched = True
                        break
                elif modifier == "endswith":
                    if event_val_str.endswith(target_val_str):
                        item_matched = True
                        break
                else:
                    if event_val_str == target_val_str:
                        item_matched = True
                        break
            
            if not item_matched:
                return False

        return True

    def _flatten_dict(self, d: dict, parent_key: str = '', sep: str = '.') -> dict:
        """
        Flattens a nested dictionary into dot notation keys.
        """
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            else:
                items.append((new_key, v))
        return dict(items)
