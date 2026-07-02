# LogXPro - Phase 1: Foundation Implementation Documentation

This document provides a detailed breakdown of the architectural components, configuration files, and setup procedures implemented during **Phase 1: Foundation (Log Collection & Storage)** of the LogXPro Autonomous SOC Engine.

---

## 1. Directory Structure

The following workspace files and directories were created during this phase:

```
LogXPro/
├── docker-compose.yml           # Core infrastructure orchestration (ELK + DBs)
├── winlogbeat.yml               # Windows Log Shipper configuration
├── setup_shipper.ps1            # Automated PowerShell installer for Sysmon & Winlogbeat
├── requirements.txt             # Python engine library dependencies
├── database/
│   └── init.sql                 # PostgreSQL DB schema initialization script
└── logstash/
    └── pipeline/
        └── logstash.conf        # Logstash parser & ECS normalization engine
```

---

## 2. Infrastructure Configuration (`docker-compose.yml`)

The infrastructure runs entirely inside containerized environments managed by [docker-compose.yml](file:///f:/projects/LogXPro/docker-compose.yml):

*   **Elasticsearch (`logxpro-elasticsearch:8.13.0`)**: Runs as a single-node log lake. Security features (`xpack.security.enabled=false`) are disabled to simplify local development API calls. To prevent resource starvation on developer laptops, memory limits are restricted to 1GB (`ES_JAVA_OPTS=-Xms1g -Xmx1g`).
*   **Kibana (`logxpro-kibana:8.13.0`)**: Bound to host port `5601`. It acts as the GUI for viewing logs, debugging, and building detection dashboard feeds.
*   **Logstash (`logxpro-logstash:8.13.0`)**: Listens on ports `5044` (Beats protocol) and `5000` (TCP JSON) to receive forwarded logs. Mounted to read `./logstash/pipeline/logstash.conf`.
*   **Redis (`logxpro-redis:7-alpine`)**: An in-memory cache used by the correlation engine to hold active session groupings (incident baskets) and execute sliding TTL expirations.
*   **PostgreSQL (`logxpro-postgres:15-alpine`)**: Relational database for metadata persistence. It mounts `init.sql` to auto-execute schemas on first startup, ensuring database tables exist out of the box.

---

## 3. Log Ingestion Pipeline (`logstash/pipeline/logstash.conf`)

[logstash.conf](file:///f:/projects/LogXPro/logstash/pipeline/logstash.conf) serves as the normalization middleware that structures raw system logs into the **Elastic Common Schema (ECS)**.

### Input Blocks
```logstash
input {
  beats { port => 5044 }   # Receives logs from Winlogbeat/Filebeat
  tcp { port => 5000, codec => json } # Allows manual mock event injection
}
```

### Ingestion-Time Stamp (The Silent Basket Killer Fix)
If endpoints drift in clock time, chronological sequence matching breaks. To solve this, Logstash stamps each log with the exact UTC arrival time using a Ruby filter:
```logstash
ruby {
  code => "event.set('[event][ingested]', Time.now.utc.iso8601(3))"
}
```

### ECS Normalization
Logstash parses Windows Sysmon logs (`Microsoft-Windows-Sysmon/Operational`) and renames non-standard fields to common terms:
*   **Sysmon Code 1 (Process Creation)**: Command line arguments map to `process.command_line`, binary paths map to `process.executable`, parent paths map to `process.parent.executable`, and process GUIDs map to `process.entity_id`. Hashes are stored under `process.hash`.
*   **Sysmon Code 3 (Network Connections)**: Maps source and destination IPs/ports to `source.ip`, `destination.ip`, etc.
*   **Sysmon Code 22 (DNS Queries)**: Renames query strings to `dns.question.name`.

---

## 4. Database Schema Setup (`database/init.sql`)

[init.sql](file:///f:/projects/LogXPro/database/init.sql) prepares PostgreSQL with the relational framework required to track incidents:

1.  **`incident_baskets`**: Grouping identity for related logs. Keyed on a UUID. Stores client GRC details, current confidence level (0-100%), and metadata of matching stages.
2.  **`basket_events`**: Stores log contents and metadata associated with a basket. Has a foreign key relationship to `incident_baskets` and deletes events cascade-style if a basket is deleted.
3.  **`enrichment_cache`**: Caches reputation lookups (IPs, hashes) from VirusTotal/AbuseIPDB/MISP for 24 hours. This prevents exhausting public API rate limits.
4.  **`alert_suppression`**: Maintains rules to mute specific rules on hosts or users, facilitating the false-positive silencing feedback loop.
5.  **`login_baseline`**: Builds geographical and chronological access patterns per user to alert on off-hours or new location anomalies.

---

## 5. Host-Side Log Shipping (`winlogbeat.yml` & `setup_shipper.ps1`)

To forward logs from the host Windows machine to the Docker log lake, we use Sysmon and Winlogbeat:

*   **[winlogbeat.yml](file:///f:/projects/LogXPro/winlogbeat.yml)**: Instructs Winlogbeat to extract security and Sysmon event logs from the Windows registry, buffer them locally, and push them to Logstash at `localhost:5044`.
*   **[setup_shipper.ps1](file:///f:/projects/LogXPro/setup_shipper.ps1)**: An automated PowerShell script (run as Administrator) that performs the following steps:
    1.  Downloads the Microsoft Sysmon utility.
    2.  Fetches SwiftOnSecurity's modular Sysmon XML configuration (which optimizes the system for security detections).
    3.  Installs Sysmon and configures it to run automatically on system boot.
    4.  Downloads Winlogbeat binaries and extracts them to `C:\Program Files\Winlogbeat`.
    5.  Copies our custom `winlogbeat.yml` into place.
    6.  Registers and starts the Winlogbeat background Windows service.

---

## 6. How to Start and Verify Phase 1

### Step A: Initialize the Infrastructure
1.  Open **Docker Desktop**.
2.  Navigate to the project root directory in your terminal and run:
    ```powershell
    docker compose up -d
    ```
3.  Confirm all five containers are running:
    ```powershell
    docker compose ps
    ```

### Step B: Install the Host Shippers
1.  Open an **Administrator PowerShell** console.
2.  Run the setup script:
    ```powershell
    Set-ExecutionPolicy Bypass -Scope Process -Force
    .\setup_shipper.ps1
    ```
3.  Confirm Winlogbeat is running:
    ```powershell
    Get-Service winlogbeat
    ```

### Step C: Verify Log Flow
1.  Access Kibana by opening your browser to `http://localhost:5601`.
2.  Navigate to **Management -> Stack Management -> Index Patterns** and create an index pattern matching `logxpro-logs-*`.
3.  Navigate to **Analytics -> Discover** to view incoming normalized Sysmon and Security events flowing in real-time.

---

## 7. Windows Environment Troubleshooting & Adaptations

During live infrastructure verification, the following corrections and modifications were made to ensure stability and compatibility on Windows:

### 7.1. Database Port Conflict (PostgreSQL)
*   **Problem**: A local PostgreSQL service (`postgresql-x64-18`) was already running on the Windows host and occupying port `5432`. When the Python engine attempted to connect to `127.0.0.1:5432`, it hit the host's database instead of the Docker container, throwing `FATAL: password authentication failed for user "soc_user"`.
*   **Resolution**: 
    1. Updated [docker-compose.yml](file:///f:/projects/LogXPro/docker-compose.yml) to map the Postgres container's port to host port **`5433`** (`5433:5432`).
    2. Updated `DB_PORT` in [settings.py](file:///f:/projects/LogXPro/soc_engine/config/settings.py) to default to `5433`.

### 7.2. IPv6 Localhost Loopback Bindings
*   **Problem**: Connecting to `"localhost"` on Windows resolved to IPv6 loopback (`::1`) which resulted in connection/routing problems inside the WSL2/Docker networks.
*   **Resolution**: Updated all default settings hosts in [settings.py](file:///f:/projects/LogXPro/soc_engine/config/settings.py) from `"localhost"` to explicit IPv4 loopback **`127.0.0.1`** (e.g. `ES_HOST = "http://127.0.0.1:9200"`).

### 7.3. Elasticsearch Library Version Incompatibility
*   **Problem**: Installing `elasticsearch` without version pins pulled version `9.4.1`. The python library sent headers requesting compatibility with v9 (`compatible-with=9`), which Elasticsearch `8.13.0` server rejected with a `BadRequestError (400)` media-type exception.
*   **Resolution**: 
    1. Pinned `elasticsearch` to `elasticsearch>=8.13.0,<9.0.0` in [requirements.txt](file:///f:/projects/LogXPro/requirements.txt).
    2. Downgraded the library in the virtual environment to `8.19.3` to match the Elasticsearch 8.x stack server compatibility.

