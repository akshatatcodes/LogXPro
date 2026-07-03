import os
import yaml
from pathlib import Path


class SigmaMatcher:
    """
    Loads Sigma-format YAML rules and evaluates log events against them.

    Supported detection fields & modifiers:
        - selection / filter blocks (filter is NOT-logic against the selection result)
        - Modifiers: |contains, |startswith, |endswith (default: exact match)
        - All values treated as case-insensitive strings

    Condition support (simplified):
        - "selection"
        - "selection and not filter"

    Note: This is an MVP evaluator purpose-built for local event matching.
    For production use with Elasticsearch backend, see the pySigma integration
    stub in docs/pysigma_integration.md.
    """

    def __init__(self, rules_dir: str = "./soc_engine/config/rules"):
        self.rules_dir = Path(rules_dir)
        self.rules = []
        self.load_rules()

    # ------------------------------------------------------------------ #
    # Rule loading                                                          #
    # ------------------------------------------------------------------ #

    def load_rules(self):
        """
        Loads and parses all Sigma YAML rules from the rules directory.
        Creates the directory and default rules if it does not yet exist.
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
                            "id":        rule_content.get("id"),
                            "title":     rule_content.get("title", "Unnamed Rule"),
                            "level":     rule_content.get("level", "medium"),
                            "detection": rule_content["detection"],
                            "logsource": rule_content.get("logsource", {}),
                            "tags":      rule_content.get("tags", []),
                            "mitre_techniques": self._extract_mitre_tags(
                                rule_content.get("tags", [])
                            ),
                        })
            except Exception as e:
                print(f"[!] Error loading Sigma rule {f}: {e}")

        print(f"[*] Loaded {len(self.rules)} Sigma rules.")

    def _extract_mitre_tags(self, tags: list) -> list:
        """
        Extracts MITRE Technique IDs (e.g. T1059.001) from rule tags.
        Tags are expected in the format 'attack.t1059.001'.
        """
        mitre_tags = []
        if tags:
            for tag in tags:
                tag_lower = tag.lower()
                if tag_lower.startswith("attack.t"):
                    tech_id = tag_lower.replace("attack.", "").upper()
                    mitre_tags.append(tech_id)
        return mitre_tags

    # ------------------------------------------------------------------ #
    # Matching entry point                                                  #
    # ------------------------------------------------------------------ #

    def match_event(self, event: dict) -> list:
        """
        Evaluates a log event against all loaded Sigma rules.

        Args:
            event: A normalised ECS-formatted log dict.

        Returns:
            List of matching rule dicts (each rule that fires).
        """
        flat_event = self._flatten_dict(event)
        matched_rules = []
        for rule in self.rules:
            if self._evaluate_rule(flat_event, rule):
                matched_rules.append(rule)
        return matched_rules

    # ------------------------------------------------------------------ #
    # Rule evaluation                                                       #
    # ------------------------------------------------------------------ #

    def _evaluate_rule(self, flat_event: dict, rule: dict) -> bool:
        """
        Evaluates a flattened event against a single Sigma rule.

        Implements a simplified condition parser:
            - "selection"                 → selection must match
            - "selection and not filter"  → selection must match AND filter must NOT match
            - "selection or ..."          → first matching group wins (simplified)
        """
        detection = rule["detection"]
        condition = detection.get("condition", "selection").lower().strip()

        # Evaluate the 'selection' group
        selection_result = self._evaluate_group(flat_event, detection.get("selection", {}))

        # Handle "selection and not filter"
        if "and not filter" in condition:
            filter_result = self._evaluate_group(flat_event, detection.get("filter", {}))
            return selection_result and not filter_result

        # Handle pure "selection"
        if condition == "selection":
            return selection_result

        # For any other condition form, fall back to just selection
        return selection_result

    def _evaluate_group(self, flat_event: dict, group: dict) -> bool:
        """
        Evaluates a single detection group (selection or filter block).
        All key-value pairs within the group are AND-ed together.
        Multiple values for the same key are OR-ed.

        Returns False for empty groups (safe default for filter blocks).
        """
        if not group:
            return False

        for key_query, target_values in group.items():
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
                    # Exact match (case-insensitive)
                    if event_val_str == target_val_str:
                        item_matched = True
                        break

            if not item_matched:
                return False

        return True

    # ------------------------------------------------------------------ #
    # Utilities                                                             #
    # ------------------------------------------------------------------ #

    def _flatten_dict(self, d: dict, parent_key: str = "", sep: str = ".") -> dict:
        """
        Recursively flattens a nested dict into dot-notation keys.
        e.g. {"process": {"command_line": "..."}} → {"process.command_line": "..."}
        """
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            else:
                items.append((new_key, v))
        return dict(items)

    def get_rule_by_id(self, rule_id: str) -> dict | None:
        """Returns a loaded rule dict by its ID, or None if not found."""
        for rule in self.rules:
            if rule.get("id") == rule_id:
                return rule
        return None

    def get_rules_for_tags(self, tags: list) -> list:
        """
        Filters loaded rules to those containing any of the given tags.
        Useful for GRC profile-based rule filtering.

        Args:
            tags: List of tag strings to match (e.g. ['attack.t1078', 'endpoint']).

        Returns:
            Subset of rules matching any of the provided tags.
        """
        tags_lower = [t.lower() for t in tags]
        return [
            rule for rule in self.rules
            if any(t.lower() in tags_lower for t in rule.get("tags", []))
        ]

    # ------------------------------------------------------------------ #
    # Default rule bootstrap                                               #
    # ------------------------------------------------------------------ #

    def _create_default_rules(self):
        """
        Writes 4 baseline Sigma rules to disk if the rules directory was empty.
        These cover the Phase 2 Phishing → C2 detection chain.
        """
        rules = {
            "win_system_rdp_bruteforce.yml": """\
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
    - attack.t1110
level: medium
""",
            "proc_creation_win_powershell_encoded_cmd.yml": """\
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
            "proc_creation_win_scheduled_task_creation.yml": """\
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
            "net_connection_win_c2_potential.yml": """\
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
""",
        }
        for name, content in rules.items():
            with open(self.rules_dir / name, "w", encoding="utf-8") as f:
                f.write(content)
        print(f"[*] Created {len(rules)} default Sigma rules in {self.rules_dir}")
