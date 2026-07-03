"""
enrichment/indicator_parser.py
-------------------------------
Phase 3: Extracts indicators of compromise (IoCs) from basket events.

Sysmon Event 1 provides hashes as a comma-separated string:
    "MD5=abc123,SHA256=def456,SHA1=ghi789"

This module normalises those into clean indicator dicts for enrichment.
"""
import re


def extract_sha256_from_sysmon(event: dict) -> str | None:
    """
    Parses the 'Hashes' field from a Sysmon Event 1 record.

    Args:
        event: Raw ECS event dict.

    Returns:
        SHA-256 hash string, or None if not found.
    """
    hashes_str = event.get("Hashes") or event.get("process", {}).get("hash", {}).get("sha256")
    if not hashes_str:
        return None

    # Handle ECS-style nested hash field
    if isinstance(hashes_str, dict):
        return hashes_str.get("sha256")

    # Handle Sysmon raw format: "MD5=abc,SHA256=def,IMPHASH=ghi"
    for part in str(hashes_str).split(","):
        part = part.strip()
        if part.upper().startswith("SHA256="):
            return part[7:]

    return None


def extract_indicators_from_basket(basket_events: list) -> dict:
    """
    Scans all basket events and extracts unique IoC lists.

    Args:
        basket_events: List of event dicts from basket_events table.

    Returns:
        {
            "ips":     ["1.2.3.4", ...],
            "hashes":  ["sha256...", ...],
            "domains": ["evil.com", ...],
        }
    """
    ips = set()
    hashes = set()
    domains = set()

    for event in basket_events:
        raw = event.get("raw_event") or {}

        # Destination IP (C2 connections)
        dest_ip = raw.get("destination", {}).get("ip")
        if dest_ip and _is_routable(dest_ip):
            ips.add(dest_ip)

        # Source IP
        src_ip = raw.get("source", {}).get("ip")
        if src_ip and _is_routable(src_ip):
            ips.add(src_ip)

        # Process hash (Sysmon Event 1)
        sha256 = extract_sha256_from_sysmon(raw)
        if sha256:
            hashes.add(sha256)

        # DNS query (Sysmon Event 22)
        dns_query = raw.get("dns", {}).get("question", {}).get("name")
        if dns_query:
            domains.add(dns_query)

    return {
        "ips":     list(ips),
        "hashes":  list(hashes),
        "domains": list(domains),
    }


# ------------------------------------------------------------------ #
# Private helpers                                                       #
# ------------------------------------------------------------------ #

_PRIVATE_RANGES = [
    re.compile(r"^10\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^127\."),
    re.compile(r"^::1$"),
    re.compile(r"^0\.0\.0\.0$"),
]


def _is_routable(ip: str) -> bool:
    """Returns True if the IP is not a private/loopback address."""
    for pattern in _PRIVATE_RANGES:
        if pattern.match(ip):
            return False
    return True
