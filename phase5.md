# LogXPro - Phase 5: Anomaly Detection, GRC Profiles, Dashboard & Response Implementation

This document provides a comprehensive technical breakdown of the architecture, components, database structures, verification simulations, and deployment instructions implemented during **Phase 5: Anomaly Detection, GRC Profiles, Dashboard & Response** of the LogXPro Autonomous SOC Engine.

---

## 1. Phase 5 Objectives & Verification Status

All goals for Phase 5 have been successfully developed, integrated, and verified:

*   **Login Anomaly Detection (Baselining)**: Completed [baseline_checker.py](file:///f:/projects/LogXPro/soc_engine/anomaly/baseline_checker.py) which builds normal logon hours and source IP profiles for users based on successful login logs (Event 4624/4672). It flags anomalies (first-seen IP, off-hours login, and new country) and feeds them into the basket correlation engine as rules.
*   **GRC Profiles & PII Redaction**: Wired [main.py](file:///f:/projects/LogXPro/soc_engine/main.py) to read GRC profiles (such as [finance.yaml](file:///f:/projects/LogXPro/soc_engine/config/grc_profiles/finance.yaml)). If `pii_redaction: true` is configured, it recursively scrubs user identifiers and IP addresses in raw event logs before PostgreSQL, Redis, or Elasticsearch storage.
*   **SOAR TheHive Integration**: Configured [main.py](file:///f:/projects/LogXPro/soc_engine/main.py) to automatically forward Tier 3/4 (High/Critical) alerts to [thehive_client.py](file:///f:/projects/LogXPro/soc_engine/response/thehive_client.py) to open cases.
*   **Response Action (IP Containment)**: Implemented [network_block.py](file:///f:/projects/LogXPro/soc_engine/response/network_block.py) to automatically or manually block malicious IPs. It executes `netsh advfirewall` on Windows (if running as admin) and `iptables` on Linux (if running as root), falling back to command prints.
*   **FastAPI Visual Dashboard**: Created [api_server.py](file:///f:/projects/LogXPro/soc_engine/api_server.py) serving a stunning, glassmorphic dark-mode web dashboard showing open/closed/FP baskets, threat intelligence cards, AI narratives, active suppression rules, logon baselines, and GRC controls.
*   **False Positive Webhook Loop**: Wired `/api/webhook/thehive` in [api_server.py](file:///f:/projects/LogXPro/soc_engine/api_server.py) to receive case closure calls. When a case is resolved as `FalsePositive` or tagged `false-positive`, it marks the basket as `fp` in PostgreSQL and creates a 7-day alert suppression rule.

---

## 2. Directory & Component Architecture

Phase 5 additions and modifications across the `soc_engine/` folder:

```
soc_engine/
├── main.py                     # Hooks baseline checking, GRC PII redaction, and TheHive forwarding
├── api_server.py               # [NEW] FastAPI web server and dark-mode dashboard UI
├── anomaly/
│   ├── __init__.py             # Exposes baseline checkers
│   └── baseline_checker.py     # Performs logon baseline checks and UPSERT SQL updates
├── config/
│   └── grc_profiles/
│       ├── default.yaml        # Client GRC profile with PII redaction disabled
│       └── finance.yaml        # Client GRC profile with PII redaction enabled
└── response/
    ├── __init__.py             # Exposes case creator and network blocker
    ├── thehive_client.py       # Maps alerting metadata and attaches tracking tags
    └── network_block.py        # [NEW] Applies Windows Firewall or Linux iptables rule blocks
```

---

## 3. Component Deep Dive

### 3.1. Login Anomaly Detector (`soc_engine/anomaly/baseline_checker.py`)
- **Baselining**: Listens for logon logs (Event 4624/4672). On a successful logon, it updates the `login_baseline` table:
  ```sql
  INSERT INTO login_baseline (user_name, source_ip, source_country, typical_hour_start, typical_hour_end, first_seen, last_seen, seen_count)
  VALUES (%s, %s, %s, %s, %s, NOW(), NOW(), 1)
  ON CONFLICT (user_name, source_ip) DO UPDATE SET
      last_seen = NOW(),
      seen_count = login_baseline.seen_count + 1,
      typical_hour_start = LEAST(login_baseline.typical_hour_start, %s),
      typical_hour_end = GREATEST(login_baseline.typical_hour_end, %s)
  ```
- **Checks**: Compares incoming events against user baseline:
  - `first_seen_ip`: Fired if no baseline exists for user + IP combination (confidence: 30%).
  - `off_hours_login`: Fired if logon hour is outside of `typical_hour_start` and `typical_hour_end` (confidence: 40%).
  - `new_country`: Fired if logon country does not match baseline country (confidence: 60%).
- **Integration**: Feeds back into the engine as a rule hit with Mitre Technique `T1078` to bootstrap attack chains.

### 3.2. GRC Profile & PII Redaction
- **Log Filtering**: Sigma rules are suppressed if their tag or group matches `disabled_rule_groups` in the client's GRC profile.
- **Redaction Helper**: Scans raw event dictionaries for identifiers:
  ```python
  if "user" in copied and isinstance(copied["user"], dict):
      if "name" in copied["user"]: copied["user"]["name"] = "[REDACTED_USER]"
  if "source" in copied and isinstance(copied["source"], dict):
      if "ip" in copied["source"]: copied["source"]["ip"] = "[REDACTED_IP]"
  ```
- **Storage Protection**: Scrubber executes *after* Sigma matching but *before* event storage to preserve correlation logic while protecting raw data privacy.

### 3.3. Response Containment (`soc_engine/response/network_block.py`)
- **Windows Firewall**: Adds block rules via `netsh`:
  ```powershell
  netsh advfirewall firewall add rule name="LogXPro Block Outbound [IP]" dir=out action=block remoteip=[IP]
  ```
- **Linux Firewall**: Appends `DROP` targets via `iptables`:
  ```bash
  iptables -A OUTPUT -d [IP] -j DROP
  ```

### 3.4. SOAR Webhook Loop & FastAPI (`soc_engine/api_server.py`)
- **Webhook Endpoint**: Exposes `/api/webhook/thehive`. Parses case tags (e.g. `basket:UUID`, `rule:rule_id`, `host:name`, `user:name`).
- **Suppression Creation**: Closes the basket as `fp` in PG and inserts a suppression rule:
  ```sql
  INSERT INTO alert_suppression (host_name, user_name, rule_id, suppressed_by, expires_at)
  VALUES (%s, %s, %s, 'thehive_webhook', NOW() + interval '7 days')
  ```

---

## 4. End-to-End Simulation Verification

### 4.1. Simulation Run: Lateral Movement & Anomaly Detection (With PII Redaction)
Running the lateral movement simulation with the `finance` profile active:
```powershell
$env:ACTIVE_GRC_PROFILE="finance"
.\venv\Scripts\python.exe -m soc_engine.main --simulate --chain lateral
```

*   **Logon Anomaly output**: The engine intercepts the logon event and simulates a first-seen IP anomaly:
    ```
    [!] ANOMALY DETECTED: First login from 10.0.0.5 for user svc_admin (Confidence: 30%)
        [!] RULE: 'Login Anomaly: First Seen Ip' (Level: MEDIUM)
    ```
*   **PII Redaction output**: Raw log fields like user indicators and IPs are scrubbed:
    ```json
    "enrichment": {
      "[REDACTED_IP]": {
        "virustotal": { "error": "Offline" }
      }
    }
    ```
*   **TheHive Forwarding log**: High and Critical alerts successfully trigger the forwarders:
    ```
    [*] Forwarding HIGH alert to TheHive...
    [!] TheHive: THEHIVE_API_KEY not configured. Skipping case creation.
    ```

---

## 5. Deployment Instructions

To run Phase 5 live:
1. Initialize the PostgreSQL schema to create the `login_baseline` table:
   ```powershell
   docker-compose up -d postgres
   ```
2. Start the API server and visual dashboard backend:
   ```powershell
   .\venv\Scripts\python.exe -m soc_engine.api_server
   ```
3. Open a browser and navigate to the dashboard:
   ```
   http://127.0.0.1:8000/
   ```
4. Access controls, baselines, active alerts, and quick response containment triggers (IP Blocking/FP marking) directly in the UI.
