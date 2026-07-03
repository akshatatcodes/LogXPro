"""
detection/yara_scanner.py
--------------------------
Phase 6: YARA rule-based scanning for process command lines, file content, and memory strings.

Falls back gracefully if `yara-python` is not installed — logs a warning and skips scanning.
In production, install with: pip install yara-python

Usage:
    from soc_engine.detection.yara_scanner import scan_string, scan_bytes, scan_file
"""
import os
import glob

_YARA_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "config", "rules", "yara")
)

_compiled_rules = None
_yara_available = False


def _load_rules():
    """Compiles all .yar files in the YARA rules directory into one combined ruleset."""
    global _compiled_rules, _yara_available

    try:
        import yara
        _yara_available = True
    except ImportError:
        print("[!] yara-python not installed. YARA scanning is disabled. Install with: pip install yara-python")
        return

    yar_files = glob.glob(os.path.join(_YARA_DIR, "*.yar"))
    if not yar_files:
        print(f"[!] No YARA rule files found in {_YARA_DIR}")
        return

    filepaths = {os.path.splitext(os.path.basename(f))[0]: f for f in yar_files}
    try:
        _compiled_rules = yara.compile(filepaths=filepaths)
        print(f"[*] YARA: Loaded {len(yar_files)} rule file(s) from {_YARA_DIR}")
    except Exception as e:
        print(f"[!] YARA compilation error: {e}")
        _compiled_rules = None


def _format_matches(raw_matches) -> list[dict]:
    """Converts yara match objects to serializable dicts."""
    results = []
    for match in raw_matches:
        results.append({
            "rule": match.rule,
            "namespace": match.namespace,
            "tags": list(match.tags),
            "meta": dict(match.meta),
            "strings": [
                {
                    "offset": s.instances[0].offset if s.instances else 0,
                    "identifier": s.identifier,
                    "data": s.instances[0].matched_data.decode("utf-8", errors="replace") if s.instances else ""
                }
                for s in match.strings
            ]
        })
    return results


def scan_string(text: str) -> list[dict]:
    """
    Scans a string (e.g. process command line) for YARA rule matches.

    Args:
        text: The string content to scan.

    Returns:
        List of match dicts (empty if no matches or YARA unavailable).
    """
    return scan_bytes(text.encode("utf-8", errors="replace"))


def scan_bytes(data: bytes) -> list[dict]:
    """
    Scans raw bytes for YARA rule matches.

    Args:
        data: The byte content to scan.

    Returns:
        List of match dicts.
    """
    if _compiled_rules is None:
        _load_rules()

    if not _yara_available or _compiled_rules is None:
        return []

    try:
        matches = _compiled_rules.match(data=data)
        result = _format_matches(matches)
        if result:
            print(f"  [YARA] {len(result)} match(es): {[m['rule'] for m in result]}")
        return result
    except Exception as e:
        print(f"[!] YARA scan_bytes error: {e}")
        return []


def scan_file(filepath: str) -> list[dict]:
    """
    Scans a file on disk for YARA rule matches.

    Args:
        filepath: Absolute path to the file.

    Returns:
        List of match dicts.
    """
    if _compiled_rules is None:
        _load_rules()

    if not _yara_available or _compiled_rules is None:
        return []

    if not os.path.isfile(filepath):
        print(f"[!] YARA scan_file: file not found at {filepath}")
        return []

    try:
        matches = _compiled_rules.match(filepath)
        result = _format_matches(matches)
        if result:
            print(f"  [YARA] File {os.path.basename(filepath)}: {len(result)} match(es): {[m['rule'] for m in result]}")
        return result
    except Exception as e:
        print(f"[!] YARA scan_file error: {e}")
        return []


def scan_basket_events(basket_events: list[dict]) -> list[dict]:
    """
    Scans all raw_event command lines / strings from basket events.
    Checks process.command_line, process.args, winlog.event_data.CommandLine.

    Returns a deduplicated list of YARA match dicts across all events.
    """
    all_matches = []
    seen_rules = set()

    for ev in basket_events:
        raw = ev.get("raw_event") or {}
        if isinstance(raw, str):
            try:
                import json
                raw = json.loads(raw)
            except Exception:
                pass

        # Try multiple common fields where command lines are stored
        cmd = (
            raw.get("process", {}).get("command_line")
            or raw.get("winlog", {}).get("event_data", {}).get("CommandLine")
            or raw.get("process", {}).get("args", "")
            or ""
        )

        if cmd and isinstance(cmd, str) and len(cmd) > 3:
            matches = scan_string(cmd)
            for m in matches:
                if m["rule"] not in seen_rules:
                    all_matches.append(m)
                    seen_rules.add(m["rule"])

    return all_matches
