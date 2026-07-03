# Phase 6 — Playbook Engine, YARA, Compliance Reporting & Production Hardening

## Overview

Phase 6 transforms LogXPro from a functional prototype into a **production-ready SOC platform**. This phase introduces four major capability pillars explicitly designed in the blueprint (§8 Playbook Engine, §2 YARA, §9.1 Compliance Reporting, §9.4 Audit Trail) plus critical API and infrastructure hardening.

---

## What Was Built

### Pillar 1 — YAML Playbook Engine

**Purpose**: Every alert should come with a set of pre-defined, context-aware response actions — not just a raw JSON payload the analyst has to interpret from scratch.

#### How it Works
1. Playbooks are defined as YAML config files in `soc_engine/config/playbooks/`.
2. At engine startup, all playbooks are compiled into an in-memory list.
3. After every alert fires, `run_playbook()` is called with the alert payload and active GRC profile.
4. The runner evaluates each playbook against `trigger_tier`, `matched_techniques`, and `matched_chain`.
5. Matching playbooks execute their `actions` in sequence.

#### Action Types
| Action | Description |
|---|---|
| `notify` | Prints a human-readable message and optionally POSTs to a Slack/Teams webhook |
| `recommend` | Appends analyst-guidance text to the alert with templated `{host}`, `{user}`, `{tier}` fields |
| `enrich` | Declares enrichment targets for the enrichment pipeline to handle |
| `auto_response` | Triggers `block_ip()` if GRC profile `auto_response_allowed: true` |

#### Playbooks Shipped
| File | Trigger | Techniques |
|---|---|---|
| `powershell_encoded.yaml` | Tier 1-4 | T1059.001 |
| `confirmed_c2_chain.yaml` | Tier 3-4 | T1071, T1486 |
| `credential_dumping.yaml` | Tier 2-4 | T1003.001, T1078 |

#### New Files
- [`soc_engine/playbooks/__init__.py`](soc_engine/playbooks/__init__.py)
- [`soc_engine/playbooks/playbook_runner.py`](soc_engine/playbooks/playbook_runner.py)
- [`soc_engine/config/playbooks/powershell_encoded.yaml`](soc_engine/config/playbooks/powershell_encoded.yaml)
- [`soc_engine/config/playbooks/confirmed_c2_chain.yaml`](soc_engine/config/playbooks/confirmed_c2_chain.yaml)
- [`soc_engine/config/playbooks/credential_dumping.yaml`](soc_engine/config/playbooks/credential_dumping.yaml)

---

### Pillar 2 — YARA File/String Scanner

**Purpose**: Blueprint §2 lists YARA rules as a detection framework alongside Sigma. This adds YARA scanning for process command lines, file content, and memory string matches extracted from basket events.

#### How it Works
1. `yara_scanner.py` loads all `.yar` files from `soc_engine/config/rules/yara/` on first use.
2. Compiles them into a single combined ruleset using `yara.compile()`.
3. `scan_basket_events()` extracts command line fields from each basket event and runs the compiled ruleset against them.
4. Matches are returned as structured dicts with `rule`, `meta`, and `strings` fields.
5. The engine (in `_handle_alert`) calls `scan_basket_events()` and appends `yara_matches` to the alert payload.
6. Falls back gracefully with a clear install message if `yara-python` is not installed.

#### YARA Rules Shipped (`generic_malware.yar`)
| Rule | Detects | MITRE |
|---|---|---|
| `Mimikatz_Strings` | sekurlsa, lsadump, privilege::debug, mimikatz | T1003.001 |
| `PowerShell_Encoded_Command` | -EncodedCommand + Base64, -WindowStyle Hidden | T1059.001 |
| `Generic_Ransomware_Indicators` | vssadmin delete shadows, ransom note strings | T1486 |
| `Suspicious_WMI_Execution` | wmic process call create, Win32_ScheduledJob | T1047 |
| `Net_User_Enumeration` | net user /domain, dsquery user | T1087.002 |

#### New Files
- [`soc_engine/detection/yara_scanner.py`](soc_engine/detection/yara_scanner.py)
- [`soc_engine/config/rules/yara/generic_malware.yar`](soc_engine/config/rules/yara/generic_malware.yar)

---

### Pillar 3 — Compliance Coverage Reporter

**Purpose**: Blueprint §9.1 explicitly calls this a "genuine differentiator" — per-client report showing which regulatory controls are actively monitored vs gaps. This is the output that satisfies audit evidence requirements.

#### How it Works
1. `generate_compliance_report(grc_profile)` loads all Sigma rule files from the `rules/` directory.
2. Extracts MITRE techniques from both `mitre_techniques` lists and standard Sigma `attack.tXXXX` tags.
3. Compares covered techniques against predefined control requirement sets for each framework:
   - **PCI-DSS v4.0** — 7 key controls
   - **HIPAA Security Rule** — 7 key controls
   - **SOX ITGC** — 5 key controls
   - **NIST CSF 2.0** — 8 key controls
4. Each control is classified: `ACTIVE` ✅, `INACTIVE` ⚠️ (rule group disabled), or `MISSING` ❌.
5. An overall coverage percentage is computed.

#### Verified Coverage (Finance Profile, PCI-DSS + SOX)
```
Overall: 83%
  PCI-DSS: 86% (6/7 controls)   — T1486 (ransomware) missing rule needed
  SOX:     80% (4/5 controls)   — T1136 (account creation persistence) needed
```

#### API Endpoint
- `GET /api/report/compliance` — Returns full JSON report
- `report_to_markdown(report)` — Renders as a Markdown table for PDF/email export

#### New Files
- [`soc_engine/reporting/__init__.py`](soc_engine/reporting/__init__.py)
- [`soc_engine/reporting/compliance_reporter.py`](soc_engine/reporting/compliance_reporter.py)

---

### Pillar 4 — Elasticsearch ILM (Index Lifecycle Management)

**Purpose**: Blueprint §9.2 mandates configurable per-client log retention tied to GRC profile's `retention_days`. Without ILM, logs accumulate forever or are deleted arbitrarily.

#### How it Works
1. `apply_ilm_policy(es_client, grc_profile)` reads `retention_days` from the active GRC profile.
2. Creates/updates an ILM policy `logxpro-ilm-policy` with:
   - **Hot phase**: Rollover at 50GB or 7 days
   - **Warm phase**: Readonly + forcemerge after 7 days
   - **Delete phase**: Purge at `retention_days` days
3. Applies an index template so all new `logxpro-*` and `soc-alerts` indices automatically use the policy.
4. Called once during `init_connections()` in live mode. Gracefully skips if ES is unreachable.

#### Client-Specific Retention
| Framework | Profile Field | Retention |
|---|---|---|
| HIPAA | `retention_days: 2190` | 6 years |
| PCI-DSS / SOX | `retention_days: 365` | 1 year |
| Default | `retention_days: 90` | 90 days |

#### New Files
- [`soc_engine/infra/__init__.py`](soc_engine/infra/__init__.py)
- [`soc_engine/infra/es_ilm.py`](soc_engine/infra/es_ilm.py)

---

### Pillar 5 — Audit Log (Evidence Trail)

**Purpose**: Blueprint §9.4: For every alert, the system must record which rule fired, which basket steps contributed, and who took action and when. This is the evidence that turns "we have detection" into "we satisfy SOC2/HIPAA/PCI audit requirements."

#### Database Schema (added to `init.sql`)
```sql
CREATE TABLE IF NOT EXISTS audit_log (
    id          SERIAL PRIMARY KEY,
    event_type  TEXT NOT NULL,   -- alert_fired | response_action:* | suppression_created | playbook_fired
    basket_id   UUID,
    rule_id     TEXT,
    tier        TEXT,
    actor       TEXT DEFAULT 'system',
    detail      JSONB DEFAULT '{}',
    created_at  TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

#### Audit Event Types
| Type | When | Actor |
|---|---|---|
| `alert_fired` | Every alert dispatch | `engine` |
| `playbook_fired` | When any playbook matches | `playbook:<id>` |
| `response_action:ip_block` | When IP is blocked | `analyst` or `playbook` |
| `suppression_created` | When FP loop suppresses | `thehive_webhook` or `analyst` |

#### API Endpoint
- `GET /api/audit?limit=100` — Returns recent audit log entries

#### New Files
- [`soc_engine/models/audit_log.py`](soc_engine/models/audit_log.py)

---

### Pillar 6 — Incident Export API

**Purpose**: Analysts need a one-click way to export the full incident context as a structured report for ticketing systems, management briefings, or forensic evidence packages.

#### API Endpoint
- `GET /api/report/basket/{basket_id}` — Returns a full Markdown incident report containing:
  - Basket metadata table (host, user, status, confidence, timestamps)
  - Attack chain stage timeline (MITRE ID, rule, timestamp per stage)
  - Event timeline (up to 20 events with type and MITRE technique)
  - Footer with engine version and generation timestamp

---

### Infrastructure & API Hardening

#### FastAPI Lifespan (Deprecation Fix)
Replaced deprecated `@app.on_event("startup")` with the modern `@asynccontextmanager lifespan` pattern. The engine background thread now starts cleanly on FastAPI v0.100+.

```python
# Before (deprecated)
@app.on_event("startup")
def startup_event(): ...

# After (Phase 6)
@asynccontextmanager
async def lifespan(app: FastAPI):
    if not os.getenv("DISABLE_ENGINE"):
        t = threading.Thread(target=run_polling_engine, daemon=True)
        t.start()
    yield

app = FastAPI(lifespan=lifespan)
```

#### CORS Middleware
Added `CORSMiddleware` with `allow_origins=["*"]` for development (tighten to specific origins in production). This enables the dashboard to be served from a separate frontend origin.

#### Health Check Endpoint
- `GET /api/health` — Returns service name, version, and ISO timestamp. Used for load balancer health checks and uptime monitoring.

#### New Settings (`settings.py`)
| Setting | Default | Purpose |
|---|---|---|
| `PLAYBOOK_DIR` | `./soc_engine/config/playbooks` | Playbook YAML directory |
| `YARA_RULES_DIR` | `./soc_engine/config/rules/yara` | YARA rules directory |
| `WEBHOOK_URL` | `""` | Slack/Teams webhook for playbook notify actions |

---

## API Surface (Complete — Phase 6)

| Method | Endpoint | Phase | Purpose |
|---|---|---|---|
| `GET` | `/` | 5 | Dark-mode SOC dashboard |
| `GET` | `/api/alerts` | 2 | All incident baskets |
| `GET` | `/api/alerts/{id}` | 2 | Basket detail + events |
| `GET` | `/api/baselines` | 5 | Login baseline entries |
| `GET` | `/api/suppressions` | 5 | Active alert suppressions |
| `GET` | `/api/grc` | 5 | Active GRC profile |
| `POST` | `/api/suppress` | 5 | Create alert suppression |
| `POST` | `/api/response/block` | 5 | Trigger IP block |
| `POST` | `/api/webhook/thehive` | 5 | FP feedback loop |
| `GET` | `/api/health` | **6** | Health check |
| `GET` | `/api/report/compliance` | **6** | GRC compliance report |
| `GET` | `/api/audit` | **6** | Audit log entries |
| `GET` | `/api/report/basket/{id}` | **6** | Full incident Markdown export |

---

## Simulation Verification

```
[*] Loaded 3 playbook(s)
[*] Loaded 3 attack chain(s)
[*] GRC Profile: Default_SOC_Client

>>> Stage 2 — PowerShell Encoded Command Execution (T1059.001)
[** TIER CHAIN -- MEDIUM] Chain: Phishing to C2 | Confidence: 50%

[PLAYBOOK] Matched: 'PowerShell Encoded Command Detected'
  [NOTIFY] [MEDIUM] PowerShell encoded command on DESKTOP-VICTIM (User: Administrator)
  [RECOMMEND] Review parent process tree...
  [ENRICH] Enrichment targets: ['process_hash', 'parent_process_hash']
  [SKIP] Auto-response disabled in playbook action.
```

Playbook engine fires correctly on T1059.001 matches ✅  
Compliance reporter runs at 83% for finance profile ✅  
All Phase 6 files pass syntax check ✅  

---

## Files Changed

| File | Change |
|---|---|
| `soc_engine/playbooks/__init__.py` | NEW |
| `soc_engine/playbooks/playbook_runner.py` | NEW |
| `soc_engine/config/playbooks/powershell_encoded.yaml` | NEW |
| `soc_engine/config/playbooks/confirmed_c2_chain.yaml` | NEW |
| `soc_engine/config/playbooks/credential_dumping.yaml` | NEW |
| `soc_engine/detection/yara_scanner.py` | NEW |
| `soc_engine/config/rules/yara/generic_malware.yar` | NEW |
| `soc_engine/reporting/__init__.py` | NEW |
| `soc_engine/reporting/compliance_reporter.py` | NEW |
| `soc_engine/infra/__init__.py` | NEW |
| `soc_engine/infra/es_ilm.py` | NEW |
| `soc_engine/models/audit_log.py` | NEW |
| `database/init.sql` | MODIFIED — added `audit_log` table + indexes |
| `soc_engine/config/settings.py` | MODIFIED — added Phase 6 settings |
| `soc_engine/main.py` | MODIFIED — playbook, YARA, audit, ILM wiring |
| `soc_engine/api_server.py` | MODIFIED — lifespan, CORS, 4 new endpoints |
