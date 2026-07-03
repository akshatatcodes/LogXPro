# LogXPro - Phase 2: Detection Engine Implementation Documentation

This document provides a comprehensive technical breakdown of the architecture, data models, logic engines, and verification simulations implemented during **Phase 2: Detection Engine (Rules, Baskets & Chains)** of the LogXPro Autonomous SOC Engine.

---

## 1. Phase 2 Objectives & Verification Status

All critical goals of Phase 2 have been successfully developed, integrated, and verified:

*   **Sigma Rule Parsing**: Built a custom, local YAML Sigma rule matcher that parses standard Sigma rules and supports string modifiers (`contains`, `startswith`, `endswith`).
*   **Active Session Grouping (Baskets)**: Implemented a two-tier session management system. It uses **Redis** for sub-millisecond lookups and sliding TTL windows, and **PostgreSQL** as the durable source of truth.
*   **Attack Chain Correlation**: Developed the correlation engine that evaluates baskets against dynamic YAML-defined multi-stage attack paths within strict sliding time windows.
*   **Tiered Alerting & Confidence Scoring**: Designed a confidence-scoring matrix (0-100%) mapped to distinct operational tiers (Tier 0 to Tier 4) and structured standard JSON alert payloads.
*   **Deduplication**: Integrated a Redis-backed token/counter mechanism to suppress alert storms.
*   **Simulation Harness**: Completed three realistic, offline-executable simulator flows (Phishing → C2, Lateral Movement, Ransomware) to test the engine end-to-end without active server connections.

---

## 2. Directory & Component Architecture

The codebase for the correlation engine resides inside the [soc_engine/](file:///f:/projects/LogXPro/soc_engine/) package:

```
soc_engine/
├── main.py                     # Entry point, polling scheduler, and simulation harness
├── config/
│   ├── settings.py             # Environment configurations, ports, and database settings
│   ├── chains/                 # YAML definitions of attack chains
│   │   ├── phishing_c2.yaml
│   │   ├── lateral_movement.yaml
│   │   └── ransomware_predeployment.yaml
│   ├── rules/                  # Active Sigma detection rules (21 files)
│   │   └── *.yml
│   └── grc_profiles/           # Client-specific governance configurations
│       ├── default.yaml
│       ├── healthcare.yaml
│       └── finance.yaml
├── ingestion/
│   └── es_reader.py            # Elasticsearch poller utilizing ingestion-time ranges
├── detection/
│   ├── sigma_matcher.py        # Local Sigma parser and event-matching engine
│   ├── basket_manager.py       # Dual-write session/basket manager (Redis + PG)
│   ├── chain_matcher.py        # Correlation engine for evaluating attack chains
│   └── tiering.py              # Confidence scorer, deduplicator, and alert builder
└── models/
    └── db.py                   # Relational database CRUD wrappers for PostgreSQL
```

---

## 3. Component Deep Dive

### 3.1. Entry Point & Scheduler (`soc_engine/main.py`)
[main.py](file:///f:/projects/LogXPro/soc_engine/main.py) manages the startup sequence, initializes active socket connections to PostgreSQL, Redis, and Elasticsearch, and coordinates the processing loops.
*   **Live Mode**: Spawns an event loop that invokes the Elasticsearch reader every `POLL_INTERVAL` seconds, passing the retrieved events to `process_log()`.
*   **Simulation Mode**: Circumvents all database/ES connections, executing mocked event sequences through the engine's match logic in-memory.

### 3.2. Elasticsearch Poller (`soc_engine/ingestion/es_reader.py`)
[es_reader.py](file:///f:/projects/LogXPro/soc_engine/ingestion/es_reader.py) queries the Elasticsearch cluster.
*   **The Ingestion-Time Constraint**: To prevent the "silent basket killer" (where endpoint clock drift shifts events out of correlation windows), the queries run range filters strictly on `event.ingested` (the time Logstash stamped the event upon arrival), rather than the endpoint local clock `@timestamp`.
*   **Scroll API Handling**: If a massive surge of events arrives (>1000 in a poll cycle), it switches to the Elasticsearch scroll context to fetch batches reliably without hitting pagination limits.

### 3.3. Sigma Rule Matcher (`soc_engine/detection/sigma_matcher.py`)
[sigma_matcher.py](file:///f:/projects/LogXPro/soc_engine/detection/sigma_matcher.py) acts as a local evaluator for Sigma rules:
*   **Dot-Notation Flattening**: System events are flat-mapped (e.g. `{"process": {"executable": "..."}}` becomes `{"process.executable": "..."}`) to allow fast key-value lookups.
*   **Modifier Support**: Evaluates rule-based wildcard indicators such as `contains`, `startswith`, and `endswith`.
*   **MITRE ATT&CK Mapping**: Evaluates tags (e.g., `attack.t1059.001`) to automatically map technique IDs to matching rules.

### 3.4. Session Basket Manager (`soc_engine/detection/basket_manager.py`)
[basket_manager.py](file:///f:/projects/LogXPro/soc_engine/detection/basket_manager.py) manages active incident session states:
*   **Session Keying**: Sessions are grouped per host machine (`active_basket:<host_name>`).
*   **Caching Strategy**: When an event fires a rule, the manager queries Redis first. If a basket ID exists, the TTL is slid forward. If Redis is empty (e.g., after an engine restart), it fetches open baskets from the PostgreSQL `incident_baskets` table. If none exist, a new database row and cache entry are created.
*   **Log Persistence**: Raw JSON logs associated with the incident are saved directly to PostgreSQL `basket_events` to build the attacker timeline.

### 3.5. Chain Correlation Matcher (`soc_engine/detection/chain_matcher.py`)
[chain_matcher.py](file:///f:/projects/LogXPro/soc_engine/detection/chain_matcher.py) loads attack path blueprints from YAML files and evaluates baskets:
*   **Time-Window Enforcement**: Iterates through all events inside the basket and filters out those occurring outside the chain's `time_window_minutes` relative to the *earliest event in the basket*.
*   **Stage Mapping**: Maps the window-filtered events to defined stages based on either the specific **Sigma rule ID** or the general **MITRE technique ID**.

### 3.6. Scoring, Deduplication & Alerting (`soc_engine/detection/tiering.py`)
[tiering.py](file:///f:/projects/LogXPro/soc_engine/detection/tiering.py) handles alert classification and rate-limiting:
*   **Scoring Formula**:
    $$\text{Confidence Score} = \left( \frac{\text{Stages Matched}}{\text{Total Chain Stages}} \right) \times 100$$
*   **Operational Tier Mapping**:
    *   **Tier 0 (Instant)**: High-criticality individual rules (e.g. Mimikatz command lines) bypass the basket requirement and alert immediately.
    *   **Tier 1 (Low)**: Confidence 1% to 49%. Logs are grouped but no active analyst notification is dispatched.
    *   **Tier 2 (Medium)**: Confidence 50% to 74%. Promoted to standard analyst triage.
    *   **Tier 3 (High)**: Confidence 75% to 99%. Triggers SOAR/TheHive automated playbooks.
    *   **Tier 4 (Critical)**: Confidence 100%. Represents a fully confirmed attack chain.
*   **Redis Deduplication**: Creates a transient Redis key `dedup:<host>:<rule>` with a 5-minute TTL. Subsequent matches within this window increment a storm counter `dedup_count:<host>:<rule>` in Redis but suppress redundant alerts.

---

## 4. Attack Chains & Rule Schema Definitions

Attack paths are dynamically configured in [soc_engine/config/chains/](file:///f:/projects/LogXPro/soc_engine/config/chains/).

### Phishing to Command & Control ([phishing_c2.yaml](file:///f:/projects/LogXPro/soc_engine/config/chains/phishing_c2.yaml))
*   **Stage 1**: Initial Access (`T1078` - RDP Logon Bruteforce or Multiple Logon Failures)
*   **Stage 2**: Execution (`T1059.001` - PowerShell Encoded Command or PowerShell Download Script)
*   **Stage 3**: Persistence (`T1053.005` - Scheduled Task Creation or Run Key Registry Edit)
*   **Stage 4**: Command and Control (`T1071` - Outbound Connection to Potential C2 or High Port Outbound Traffic)
*   **Scoring Profile**: Fires a Medium alert at 50% confidence (2 stages matched), rising to Critical at 100% (all 4 stages matched).

### Lateral Movement ([lateral_movement.yaml](file:///f:/projects/LogXPro/soc_engine/config/chains/lateral_movement.yaml))
*   **Stage 1**: Privilege Abuse (`T1078.002` - Special Privilege Logon)
*   **Stage 2**: Credential Dumping (`T1003.001` - Mimikatz Tool Usage or LSASS Procdump)
*   **Stage 3**: Lateral Execution (`T1021.002` - WMI process creation or SMB Lateral Connection)
*   **Stage 4**: Discovery (`T1087.002` - Net User Domain Enumeration or Trust Discovery)

### Ransomware Pre-Deployment ([ransomware_predeployment.yaml](file:///f:/projects/LogXPro/soc_engine/config/chains/ransomware_predeployment.yaml))
*   **Stage 1**: Defense Evasion (`T1562.001` - Windows Defender disabling or Security Service stop via sc.exe)
*   **Stage 2**: Data Destruction (`T1490` - Volume Shadow Copy deletion via vssadmin or wmic)
*   **Stage 3**: Execution (`T1059.001` - Encoded PowerShell Payload Dropper)

---

## 5. Verification Simulations

We executed end-to-end simulations on the correlation engine package. All test logs triggered rule mappings, basket updates, confidence scaling, and alerting logic successfully.

### 5.1. Simulation 1: Phishing to C2
```powershell
.\venv\Scripts\python.exe -m soc_engine.main --simulate
```
*   **Trace Output**:
    1.  **Event 1 (Logon Failure)** matches `win_system_rdp_bruteforce`. Active basket initialized (`Confidence: 25%`).
    2.  **Event 2 (PowerShell encoded execution)** matches `proc_creation_win_powershell_encoded_cmd`. Basket confidence hits `50%`. Fires **`[** TIER CHAIN -- MEDIUM]`**.
    3.  **Event 3 (Scheduled Task)** matches `proc_creation_win_scheduled_task_creation`. Basket confidence hits `75%`. Fires **`[** TIER CHAIN -- HIGH]`**.
    4.  **Event 4 (Outbound IP 5.5.5.5)** matches `net_connection_win_c2_potential`. Basket confidence hits `100%`. Fires **`[** TIER CHAIN -- CRITICAL]`**.

### 5.2. Simulation 2: Lateral Movement
```powershell
.\venv\Scripts\python.exe -m soc_engine.main --simulate --chain lateral
```
*   **Trace Output**:
    1.  **Event 1 (Special Logon)** triggers `win_special_privilege_logon` (`Confidence: 25%`).
    2.  **Event 2 (Mimikatz)** triggers `proc_creation_win_mimikatz`. Since the rule level is `critical`, it fires a **`[!! TIER 0 -- INSTANT CRITICAL]`** alert immediately. It also updates the basket to `Confidence: 50%`, triggering a **`[** TIER CHAIN -- MEDIUM]`** alert.
    3.  **Event 3 (WMI process spawn)** triggers `proc_creation_win_wmi_spawns_process` (`Confidence: 75%`, **`[** TIER CHAIN -- HIGH]`**).
    4.  **Event 4 (Domain enum)** triggers `proc_creation_win_net_user_enum` (`Confidence: 100%`, **`[** TIER CHAIN -- CRITICAL]`**).

### 5.3. Simulation 3: Ransomware Pre-Deployment
```powershell
.\venv\Scripts\python.exe -m soc_engine.main --simulate --chain ransomware
```
*   **Trace Output**:
    1.  **Event 1 (Defender Disable)** matches `proc_creation_win_defender_disable` (`Confidence: 33%`, below alert threshold).
    2.  **Event 2 (SC stop VSS)** matches `proc_creation_win_sc_stop_security` (Keeps confidence at `33%` since it's the same stage type `T1562.001`).
    3.  **Event 3 (Vssadmin delete shadows)** matches `proc_creation_win_vssadmin_delete_shadows`. Hits `Confidence: 66%`, triggering **`[** TIER CHAIN -- MEDIUM]`**.
    4.  **Event 4 (Payload execution)** matches `proc_creation_win_powershell_encoded_cmd`. Hits `Confidence: 100%`, triggering **`[** TIER CHAIN -- CRITICAL]`**.

---

## 6. How to Deploy & Verify Phase 2 Live

1.  Start the container infrastructure (from Phase 1):
    ```powershell
    docker compose up -d
    ```
2.  Launch the polling engine in live mode:
    ```powershell
    .\venv\Scripts\python.exe -m soc_engine.main
    ```
3.  Inject mock logs into Logstash to test live matching (Logstash listens on port `5000` TCP for JSON):
    ```powershell
    # Send a process creation event matching powershell -enc
    echo '{"host":{"name":"DESKTOP-VICTIM"},"user":{"name":"Administrator"},"event":{"code":1},"process":{"executable":"powershell.exe","command_line":"powershell.exe -enc SQBFAFMAIAAoAE4A...","entity_id":"{a398-0001}"}}' | NC 127.0.0.1 5000
    ```
4.  Check the correlation engine terminal window to verify live rule hits, basket creation, database additions, and console alerts.
