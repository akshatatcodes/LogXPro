# LogXPro - Phase 3: Threat Intelligence & Enrichment Implementation Documentation

This document provides a comprehensive technical breakdown of the architecture, components, API integrations, caching mechanisms, and mock simulation routines implemented during **Phase 3: Enrichment & Threat Intelligence** of the LogXPro Autonomous SOC Engine.

---

## 1. Phase 3 Objectives & Verification Status

All goals for Phase 3 have been successfully implemented, verified, and integrated into the core log correlation pipeline:

*   **Indicator Parsing & Extraction**: Implemented an automated parser ([indicator_parser.py](file:///f:/projects/LogXPro/soc_engine/enrichment/indicator_parser.py)) that inspects all events in a session basket, filters out private/non-routable IPs (RFC1918), normalizes Sysmon Event 1 hashes (extracting SHA256), and extracts Sysmon Event 22 DNS queries.
*   **Enrichment Cache**: Created a database cache layer ([cache.py](file:///f:/projects/LogXPro/soc_engine/enrichment/cache.py)) writing to the PostgreSQL `enrichment_cache` table with a configurable 24-hour Time-to-Live (TTL) to protect free API rate-limits and optimize runtime speed.
*   **VirusTotal Integration**: Developed a wrapper ([virustotal.py](file:///f:/projects/LogXPro/soc_engine/enrichment/virustotal.py)) for the VirusTotal v3 REST API to check reputation scores for IPs, file hashes, and domains.
*   **AbuseIPDB Integration**: Developed a client wrapper ([abuseipdb.py](file:///f:/projects/LogXPro/soc_engine/enrichment/abuseipdb.py)) querying the AbuseIPDB v2 endpoint to retrieve confidence scores, reports, and geolocation details for IP addresses.
*   **MISP Integration**: Integrated a local threat intel lookup client ([misp_client.py](file:///f:/projects/LogXPro/soc_engine/enrichment/misp_client.py)) utilizing PyMISP to cross-reference indicators against self-hosted intelligence feeds.
*   **Orchestration Engine**: Built an enrichment orchestrator ([orchestrator.py](file:///f:/projects/LogXPro/soc_engine/enrichment/orchestrator.py)) that fetches indicators, invokes checks, merges verdicts into a unified intelligence envelope, and attaches it directly to the alert payload.
*   **Simulation & Mock Support**: Injected high-fidelity mock intelligence indicators directly into the orchestrator so simulations (`--simulate`) run offline (or without configured API keys) and demonstrate exactly how suspicious processes and C2 IPs are enriched.

---

## 2. Directory & Component Architecture

All threat intelligence and enrichment files reside in the [soc_engine/enrichment/](file:///f:/projects/LogXPro/soc_engine/enrichment/) directory:

```
soc_engine/
├── main.py                          # Integrates and executes the orchestrator in live & sim loops
├── config/
│   └── settings.py                  # Defines VT, AbuseIPDB, and MISP API settings / credentials
└── enrichment/
    ├── __init__.py                  # Exposes the primary orchestrator entry point
    ├── cache.py                     # PostgreSQL enrichment caching read/write layer
    ├── indicator_parser.py          # Extractor logic for file hashes, routable IPs, and DNS queries
    ├── virustotal.py                # Client wrapper for VirusTotal API v3
    ├── abuseipdb.py                 # Client wrapper for AbuseIPDB API v2
    ├── misp_client.py               # Local PyMISP API wrapper
    └── orchestrator.py              # Central engine calling clients, checks, and caching
```

---

## 3. Component Deep Dive

### 3.1. Indicator Parser (`soc_engine/enrichment/indicator_parser.py`)
[indicator_parser.py](file:///f:/projects/LogXPro/soc_engine/enrichment/indicator_parser.py) extracts unique Indicators of Compromise (IoCs) from a basket:
*   **Sysmon Hash Parsing**: Extracting SHA256 hashes from process creation events (Sysmon Event 1). It handles both standard string hashes (e.g. `"MD5=...,SHA256=4b6842bf...,SHA1=..."`) and ECS-style nested maps (`process.hash.sha256`).
*   **Private IP Filtering**: Uses regular expressions to filter out private IP addresses (RFC1918 subnets `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopbacks (`127.0.0.1`, `::1`), and broadcast addresses (`0.0.0.0`). This keeps private logs clean and prevents unnecessary threat intel queries.
*   **DNS Extraction**: Extracts queried domains directly from DNS request logs (Sysmon Event 22).

### 3.2. Cache Controller (`soc_engine/enrichment/cache.py`)
[cache.py](file:///f:/projects/LogXPro/soc_engine/enrichment/cache.py) handles persistence to avoid API exhaustion:
*   **TTL Checks**: Inquiries retrieve `verdict` and `checked_at` from the `enrichment_cache` table. A cache hit is valid if the age is under 24 hours (`CACHE_TTL_HOURS = 24`). Otherwise, it flags a cache miss.
*   **Database Writeups**: Stores clean JSON serialization of verdicts. It leverages `ON CONFLICT (indicator, source) DO UPDATE` commands in PostgreSQL to handle state changes seamlessly.

### 3.3. VirusTotal Client (`soc_engine/enrichment/virustotal.py`)
[virustotal.py](file:///f:/projects/LogXPro/soc_engine/enrichment/virustotal.py) integrates with VirusTotal's v3 JSON API:
*   **Endpoints**: Checks `/ip_addresses/{ip}`, `/files/{hash}`, and `/domains/{domain}`.
*   **Response Model**: Normalizes attributes into a simplified payload containing:
    *   `malicious` & `suspicious` AV vendor detection counts.
    *   `total` engines checked.
    *   Metadata fields like `country`, `asn`, file `name`, file `type`, and domain `registrar`.

### 3.4. AbuseIPDB Client (`soc_engine/enrichment/abuseipdb.py`)
[abuseipdb.py](file:///f:/projects/LogXPro/soc_engine/enrichment/abuseipdb.py) integrates with the AbuseIPDB check API:
*   **Parameter Tuning**: Queries `/check` with a `maxAgeInDays=90` window.
*   **Reputation Metrics**: Extracts `abuseConfidenceScore` (0-100% severity), `totalReports`, `countryCode`, `domain`, `isp`, and `isTor` indicators.

### 3.5. PyMISP Lookup Client (`soc_engine/enrichment/misp_client.py`)
[misp_client.py](file:///f:/projects/LogXPro/soc_engine/enrichment/misp_client.py) queries self-hosted MISP platforms:
*   **Connection Resilience**: Disables urllib3 InsecureRequestWarnings to allow development instances with self-signed SSL certificates (`ssl=False`).
*   **Attribute Tagging**: Iterates through matching threat events, extracting OSINT attribution, adversary descriptors, and threat levels (e.g. `threat_actor:CobaltGroup`, `misp:malware-type="Credential Stealer"`).

### 3.6. Orchestrator & Mock Harness (`soc_engine/enrichment/orchestrator.py`)
[orchestrator.py](file:///f:/projects/LogXPro/soc_engine/enrichment/orchestrator.py) links all components:
*   **Unified Lookup Logic**: Takes the list of event records, parses out IPs, hashes, and domains, and fires parallelized synchronous check tasks.
*   **Mock Verification Override**: If the engine runs in simulation mode (or API keys are unconfigured), the orchestrator intercepts the query and matches indicators against predefined high-fidelity mock threats:
    *   `203.0.113.99`: Mocked AWS-hosted Cobalt Strike Command & Control server with 14 malicious VT hits and an AbuseIPDB confidence score of 85%.
    *   `4b6842bf8276eac8677250a98956ff34d5678ab3e456cde90f123456789abcde`: Mocked Mimikatz executable flagged by 58 AV vendors and classified in MISP as a high-threat credential stealer.

---

## 4. Database Schema

The enrichment cache references the following SQL table (originally generated in Phase 1):

```sql
CREATE TABLE enrichment_cache (
  indicator TEXT NOT NULL,
  indicator_type TEXT NOT NULL,   -- ip | domain | hash
  source TEXT NOT NULL,           -- virustotal | abuseipdb | misp
  verdict JSONB,
  checked_at TIMESTAMP DEFAULT NOW(),
  PRIMARY KEY (indicator, source)
);
```

---

## 5. End-to-End Simulation Verification

Testing demonstrates that alerts promoted to Tier 2 (Medium) or higher automatically trigger the enrichment orchestrator.

### 5.1. Phishing to C2 Simulation (IP Reputation Threat Intel)
```powershell
.\venv\Scripts\python.exe -m soc_engine.main --simulate --chain phishing
```
*   **Verification Result**: Once the simulation hits the fourth stage (Outbound C2 Connection to `203.0.113.99`), the orchestrator triggers. Because this is a simulation, it retrieves the mock reputation records and appends them to the payload under `enrichment`:
```json
  "enrichment": {
    "203.0.113.99": {
      "virustotal": {
        "malicious": 14,
        "suspicious": 2,
        "total": 72,
        "country": "US",
        "asn": 16509,
        "note": "Simulated C2 server detection"
      },
      "abuseipdb": {
        "abuse_score": 85,
        "total_reports": 412,
        "country": "US",
        "domain": "amazonaws.com",
        "isp": "Amazon.com, Inc.",
        "is_tor": false,
        "note": "Simulated high abuse score"
      },
      "misp": {
        "found": true,
        "event_count": 1,
        "tags": [
          "Type:OSINT",
          "tlp:white",
          "threat_actor:CobaltGroup",
          "adversary:Cobalt Strike"
        ]
      }
    }
  }
```

### 5.2. Lateral Movement Simulation (File Hash Threat Intel)
```powershell
.\venv\Scripts\python.exe -m soc_engine.main --simulate --chain lateral
```
*   **Verification Result**: The Mimikatz credential dump matches the `proc_creation_win_mimikatz` rule (Tier 0 Critical). The basket confidence escalates to 50% (Tier Chain Medium), which immediately executes the enrichment. The parser extracts the process SHA256 file hash and enriches it:
```json
  "enrichment": {
    "4b6842bf8276eac8677250a98956ff34d5678ab3e456cde90f123456789abcde": {
      "virustotal": {
        "malicious": 58,
        "suspicious": 1,
        "total": 70,
        "name": "mimikatz.exe",
        "type": "Win32 EXE",
        "note": "Simulated Mimikatz credential dumper"
      },
      "misp": {
        "found": true,
        "event_count": 3,
        "tags": [
          "misp:malware-type=\"Credential Stealer\"",
          "threat_level:high"
        ]
      }
    }
  }
```

### 5.3. Ransomware Simulation (Empty Indicators Check)
```powershell
.\venv\Scripts\python.exe -m soc_engine.main --simulate --chain ransomware
```
*   **Verification Result**: The ransomware execution completes all stages successfully. However, because no external IP connections, file hashes, or DNS queries occur in this simulation flow, the orchestrator returns `"enrichment": {}` safely without throwing an exception or querying APIs with empty arguments.

---

## 6. How to Configure live API Credentials

To run Phase 3 live with actual APIs:
1. Open [soc_engine/config/settings.py](file:///f:/projects/LogXPro/soc_engine/config/settings.py) or set environment variables:
   ```powershell
   $env:VT_API_KEY="your_virustotal_api_key"
   $env:ABUSEIPDB_API_KEY="your_abuseipdb_api_key"
   $env:MISP_URL="https://your-misp-domain"
   $env:MISP_API_KEY="your_misp_auth_key"
   ```
2. Launch the live correlation engine:
   ```powershell
   .\venv\Scripts\python.exe -m soc_engine.main
   ```
3. Any alert crossing the Medium tier threshold (confidence $\ge 50\%$) will verify PostgreSQL cache records, fetch real-time verdicts from VirusTotal, AbuseIPDB, or MISP when required, cache the updates, and include threat intelligence results.
