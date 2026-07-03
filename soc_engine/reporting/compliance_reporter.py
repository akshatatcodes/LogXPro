"""
reporting/compliance_reporter.py
----------------------------------
Phase 6: Generates per-client compliance coverage reports.

Maps the active GRC profile against loaded Sigma rules to produce:
  - ACTIVE controls (rule group enabled, rules loaded)
  - INACTIVE controls (rule group explicitly disabled in profile)
  - MISSING coverage (no rule covers a known MITRE technique)

Supports PCI-DSS, HIPAA, SOX, NIST frameworks.
Returns structured JSON or Markdown for use in the dashboard and export API.
"""
import os
import glob
import yaml

# --------------------------------------------------------------------------- #
# Framework control definitions                                               #
# Maps each compliance framework to the rule groups and MITRE techniques      #
# that are required to satisfy its controls.                                  #
# --------------------------------------------------------------------------- #
FRAMEWORK_CONTROLS = {
    "pci-dss": {
        "name": "PCI-DSS v4.0",
        "required_groups": ["active_directory", "network", "endpoint", "email"],
        "required_techniques": {
            "T1078": "Req 8.2 — Account Management / Valid Account Control",
            "T1110": "Req 8.3 — Brute Force / Authentication Controls",
            "T1059.001": "Req 6.3 — Script Execution / Application Security",
            "T1071": "Req 10.2 — Network Monitoring / C2 Detection",
            "T1486": "Req 12.10 — Ransomware / IR Procedures",
            "T1021.002": "Req 7.2 — Network Access Control / Lateral Movement",
            "T1003.001": "Req 8.2 — Credential Protection / LSASS",
        }
    },
    "hipaa": {
        "name": "HIPAA Security Rule",
        "required_groups": ["active_directory", "endpoint", "email", "database"],
        "required_techniques": {
            "T1078": "§164.312(d) — Person Authentication",
            "T1110": "§164.312(a) — Access Control / Failed Logons",
            "T1530": "§164.312(a) — Data in Cloud Storage",
            "T1059.001": "§164.312(b) — Audit Controls / PowerShell",
            "T1071": "§164.312(e) — Transmission Security / C2",
            "T1486": "§164.308(a)(7) — Contingency Plan / Ransomware",
            "T1087.002": "§164.308(a)(5) — Security Awareness / Enumeration",
        }
    },
    "sox": {
        "name": "SOX ITGC",
        "required_groups": ["active_directory", "endpoint", "network"],
        "required_techniques": {
            "T1078": "ITGC-1 — Access Management / Valid Accounts",
            "T1003.001": "ITGC-2 — Privileged Access / Credential Dumping",
            "T1136": "ITGC-3 — Account Provisioning / Persistence",
            "T1059.001": "ITGC-4 — Change Management / PowerShell",
            "T1021.002": "ITGC-5 — Segregation of Duties / Lateral Movement",
        }
    },
    "nist": {
        "name": "NIST CSF 2.0",
        "required_groups": ["active_directory", "endpoint", "network", "email"],
        "required_techniques": {
            "T1078": "ID.AM-3 — Asset Management / Account Tracking",
            "T1110": "PR.AC-1 — Access Control / Auth Policy",
            "T1059.001": "DE.CM-3 — Continuous Monitoring / Script Execution",
            "T1071": "DE.CM-1 — Network Monitoring / C2",
            "T1486": "RC.RP-1 — Recovery Planning / Ransomware",
            "T1003.001": "PR.AC-4 — Access Management / Credential Protection",
            "T1053.005": "PR.IP-1 — Baseline Config / Scheduled Tasks",
            "T1021.002": "DE.CM-7 — Monitoring / Unauthorized Lateral Movement",
        }
    }
}


def _load_sigma_rules(rules_dir: str) -> list[dict]:
    """Loads all Sigma rule YAML files (.yaml and .yml) and returns them as dicts."""
    rules = []
    for pattern in ["*.yaml", "*.yml"]:
        for filepath in glob.glob(os.path.join(rules_dir, "**", pattern), recursive=True):
            # Skip YARA subdirectory
            if os.sep + "yara" + os.sep in filepath or filepath.endswith(".yar"):
                continue
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    rule = yaml.safe_load(f)
                    if rule and isinstance(rule, dict):
                        rules.append(rule)
            except Exception:
                pass
    return rules



def _get_all_covered_techniques(sigma_rules: list[dict], enabled_groups: list[str]) -> set[str]:
    """
    Extracts all MITRE technique IDs from active (enabled-group) Sigma rules.
    Handles both:
      - mitre_techniques: [T1059.001]  (custom format)
      - tags: [attack.t1059.001]       (standard Sigma format)
    """
    covered = set()
    for rule in sigma_rules:
        rule_group = rule.get("group", "")
        rule_tags = [t.lower() for t in rule.get("tags", [])]

        # A rule is active if:
        #   - no enabled_groups filter is applied (empty list = all active), OR
        #   - the rule explicitly has a matching group field, OR
        #   - the rule has no group field at all (treat as globally applicable)
        if enabled_groups:
            group_active = (
                not rule_group  # no group set → treat as active
                or rule_group in enabled_groups
                or any(g.lower() in rule_tags for g in enabled_groups)
            )
        else:
            group_active = True

        if group_active:
            # Method 1: explicit mitre_techniques list
            for t in rule.get("mitre_techniques", []):
                covered.add(t.upper())

            # Method 2: standard Sigma attack tags — attack.t1059.001 → T1059.001
            for tag in rule.get("tags", []):
                tag_lower = tag.lower()
                if tag_lower.startswith("attack.t"):
                    # Extract the technique ID part after "attack."
                    tech_id = tag[len("attack."):].upper()
                    covered.add(tech_id)
    return covered




def generate_compliance_report(grc_profile: dict, rules_dir: str = None) -> dict:
    """
    Generates a full compliance coverage report for the active GRC profile.

    Args:
        grc_profile: The loaded GRC profile dict.
        rules_dir: Path to the Sigma rules directory. Auto-resolved if None.

    Returns:
        Dict with framework-by-framework coverage breakdown.
    """
    if rules_dir is None:
        rules_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "config", "rules")
        )

    sigma_rules = _load_sigma_rules(rules_dir)
    enabled_groups = grc_profile.get("enabled_rule_groups", [])
    disabled_groups = grc_profile.get("disabled_rule_groups", [])
    active_frameworks = [f.lower() for f in grc_profile.get("frameworks", list(FRAMEWORK_CONTROLS.keys()))]

    covered_techniques = _get_all_covered_techniques(sigma_rules, enabled_groups)

    report = {
        "client": grc_profile.get("client", "Unknown"),
        "industry": grc_profile.get("industry", "generic"),
        "active_frameworks": active_frameworks,
        "enabled_rule_groups": enabled_groups,
        "disabled_rule_groups": disabled_groups,
        "total_sigma_rules_loaded": len(sigma_rules),
        "total_techniques_covered": len(covered_techniques),
        "frameworks": {}
    }

    for fw_key, fw_def in FRAMEWORK_CONTROLS.items():
        if active_frameworks and fw_key not in active_frameworks:
            # Skip frameworks not in this client's profile
            continue

        fw_result = {
            "name": fw_def["name"],
            "required_groups": fw_def["required_groups"],
            "controls": {
                "active": [],
                "inactive": [],
                "missing": []
            },
            "coverage_percent": 0
        }

        total_controls = len(fw_def["required_techniques"])
        active_count = 0

        for mitre_id, control_desc in fw_def["required_techniques"].items():
            # Check if any of the required groups for this framework are disabled
            group_disabled = any(g in disabled_groups for g in fw_def["required_groups"])

            if mitre_id in covered_techniques:
                fw_result["controls"]["active"].append({
                    "mitre_id": mitre_id,
                    "description": control_desc,
                    "status": "ACTIVE"
                })
                active_count += 1
            elif group_disabled:
                fw_result["controls"]["inactive"].append({
                    "mitre_id": mitre_id,
                    "description": control_desc,
                    "status": "INACTIVE",
                    "reason": f"Rule group disabled in GRC profile"
                })
            else:
                fw_result["controls"]["missing"].append({
                    "mitre_id": mitre_id,
                    "description": control_desc,
                    "status": "MISSING",
                    "reason": "No Sigma rule covers this technique"
                })

        fw_result["coverage_percent"] = round((active_count / total_controls) * 100) if total_controls else 0
        fw_result["active_count"] = active_count
        fw_result["total_controls"] = total_controls
        report["frameworks"][fw_key] = fw_result

    # Overall summary
    all_active = sum(len(fw["controls"]["active"]) for fw in report["frameworks"].values())
    all_total = sum(fw["total_controls"] for fw in report["frameworks"].values())
    report["overall_coverage_percent"] = round((all_active / all_total) * 100) if all_total else 0

    return report


def report_to_markdown(report: dict) -> str:
    """Renders the compliance report dict as a human-readable Markdown string."""
    lines = [
        f"# LogXPro Compliance Coverage Report",
        f"**Client**: {report['client']} | **Industry**: {report['industry'].upper()}",
        f"**Overall Coverage**: {report['overall_coverage_percent']}% across {len(report['frameworks'])} framework(s)",
        f"**Total Sigma Rules Loaded**: {report['total_sigma_rules_loaded']}",
        f"**MITRE Techniques Covered**: {report['total_techniques_covered']}",
        ""
    ]

    for fw_key, fw in report["frameworks"].items():
        lines += [
            f"## {fw['name']} — {fw['coverage_percent']}% Coverage ({fw['active_count']}/{fw['total_controls']} controls)",
            "",
            "| MITRE ID | Control | Status |",
            "|---|---|---|"
        ]
        for c in fw["controls"]["active"]:
            lines.append(f"| {c['mitre_id']} | {c['description']} | ✅ ACTIVE |")
        for c in fw["controls"]["inactive"]:
            lines.append(f"| {c['mitre_id']} | {c['description']} | ⚠️ INACTIVE — {c.get('reason', '')} |")
        for c in fw["controls"]["missing"]:
            lines.append(f"| {c['mitre_id']} | {c['description']} | ❌ MISSING — {c.get('reason', '')} |")
        lines.append("")

    return "\n".join(lines)
