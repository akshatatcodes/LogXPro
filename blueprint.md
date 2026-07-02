# Autonomous SOC Correlation & Investigation Engine
## Full Architecture Blueprint (100% Free / Open-Source Stack)

---

## 1. Project Goal (One Line)

Automatically collect logs from every endpoint/service, correlate scattered events into a single attacker timeline using predefined MITRE ATT&CK patterns, enrich it with free threat intel, and generate a ready-to-read incident narrative — so the analyst opens *one* alert instead of investigating ten.

---

## 2. Complete Component List (All Free / Open-Source)

### Log Sources
- Windows Event Logs (Security, System, PowerShell Operational)
- Sysmon (process creation, network connections, registry, file events)
- Linux auditd / syslog
- Zeek (network metadata)
- DNS query logs (Windows DNS, BIND, Pi-hole)
- Web server logs (Nginx/Apache)
- Email logs (mail server / O365 message trace export)
- Firewall logs (pfSense, iptables)
- Active Directory logs (logon, Kerberos, privilege changes)
- Cloud logs if applicable (AWS CloudTrail free tier, Azure Activity Log)

### Collection & Pipeline
- Filebeat / Winlogbeat — ship logs from endpoints
- Logstash — parsing & normalization into ECS format
- Redis — short-term correlation buffer (in-memory basket store)

### Storage
- Elasticsearch (or OpenSearch, fully free fork) — central log lake
- PostgreSQL — incident metadata, rule configs, GRC profiles
- ChromaDB — vector store for RAG knowledge base

### Detection Frameworks
- Sigma rules (free, community-maintained)
- YARA rules
- MITRE ATT&CK STIX/JSON dataset (free download)
- Atomic Red Team / Caldera — for generating test attack logs in your lab

### Free Threat Intel / Enrichment APIs
- VirusTotal public API (rate-limited, free)
- AbuseIPDB free tier
- URLhaus free API
- MISP (self-hosted, free) — your own threat intel store
- OpenCTI (self-hosted, free) — optional, for organizing intel

### File Reputation (No Sandbox — Hash Lookup Only)
- VirusTotal / Hybrid Analysis free API — check file hashes from email attachments against known-malware databases (no local sandbox infrastructure needed)

### Correlation Engine
- Python 3 + FastAPI — your custom logic layer
- APScheduler or Celery — for periodic correlation jobs

### AI / RAG
- Ollama — run Llama 3 or Mistral locally, $0 API cost
- LangChain — orchestration between logs, ChromaDB, and the LLM
- ChromaDB — already listed above

### Response / Ticketing
- TheHive (free, open-source SOAR/case management)
- Snort or Suricata — free IDS/IPS, can issue block rules

### Visualization
- Kibana (free with Elasticsearch/OpenSearch) for fast MVP
- React + D3.js — for a custom attack-timeline dashboard later

### Infra
- Docker + Docker Compose — to package everything into one deployable stack

**Nothing on this list requires a paid license for the scale of an MVP or small/medium deployment.**

---

## 3. Architecture Diagram (Text Form)

```
┌──────────────────────────┐
│      1. LOG SOURCES       │
│  Sysmon / Zeek / DNS /    │
│  AD / Firewall / Email /  │
│  Web / Cloud              │
└────────────┬──────────────┘
             │ (Filebeat / Winlogbeat agents)
             ▼
┌──────────────────────────┐
│   2. INGESTION LAYER      │
│  Logstash → normalize ECS │
│  Redis → short-term buffer│
└────────────┬──────────────┘
             ▼
┌──────────────────────────┐
│   3. STORAGE LAYER        │
│  Elasticsearch (log lake) │
│  PostgreSQL (metadata)    │
└────────────┬──────────────┘
             ▼
┌────────────────────────────────────────┐
│   4. CORRELATION ENGINE (Python/FastAPI) │
│  a) Sigma/YARA single-event matching     │
│  b) Basket builder (host/user/proc/IP/   │
│     time-window grouping)                │
│  c) Sequence matcher vs predefined       │
│     MITRE attack chains                  │
│  d) GRC/Industry profile filter          │
│     (turns rule groups on/off per client)│
└────────────┬─────────────────────────────┘
             │ (only fires when sequence matches)
             ▼
┌──────────────────────────┐
│  5. ENRICHMENT LAYER      │
│  VirusTotal / AbuseIPDB / │
│  URLhaus / MISP           │
│  attachment hash lookup   │
└────────────┬──────────────┘
             ▼
┌──────────────────────────┐
│  6. AI / RAG NARRATIVE    │
│  ChromaDB (MITRE +        │
│  past incidents) +        │
│  LangChain + Ollama LLM   │
│  → plain-English summary  │
└────────────┬──────────────┘
             ▼
┌──────────────────────────┐
│  7. OUTPUT & RESPONSE     │
│  Dashboard (Kibana/React) │
│  TheHive ticket           │
│  Snort/firewall block     │
│  (human approval gate)    │
└──────────────────────────┘
```

---

## 4. How It Actually Works — Step-by-Step Flow

**Step 1 — Collection**
Agents (Filebeat/Winlogbeat/Sysmon) sit on every endpoint and forward raw logs continuously to Logstash.

**Step 2 — Normalization**
Logstash reshapes every log type (Windows event, Zeek record, DNS query, firewall log) into one common schema (ECS), so a "source IP" field means the same thing no matter which log it came from. This is the step most homemade projects skip, and it's why correlation later actually works.

**Step 3 — Storage**
Normalized events land in Elasticsearch, searchable and indexed in near real time.

**Step 4 — Correlation (the core engine)**
A Python service polls Elasticsearch for new events and:
- Checks each event against Sigma/YARA rules for known-bad single indicators.
- Groups events sharing the same host, user, process lineage, or source IP into a temporary "incident basket" held in Redis.
- Continuously checks each basket against your predefined attack sequences (e.g., Logon → PowerShell → Persistence → Outbound C2). Only when a full sequence is matched does it escalate the basket into a confirmed incident — this is what prevents false-positive flooding.
- Applies the client's GRC/industry profile (see Section 6) to decide which rule groups are even active for that environment.

**Step 5 — Enrichment**
Once an incident is confirmed, the engine automatically pulls every IP, domain, and file hash involved and queries VirusTotal, AbuseIPDB, URLhaus, and your own MISP instance. If an email attachment is part of the chain, its file hash is checked against VirusTotal/Hybrid Analysis for known-malware matches — no local sandbox detonation is needed for the MVP.

**Step 6 — AI Narrative**
The full incident object (TTPs, enrichment results, sandbox report) is handed to LangChain, which retrieves relevant MITRE technique text and any similar past incidents from ChromaDB, then prompts the local LLM (via Ollama) to write a human-readable summary and suggested containment steps. The AI only narrates — it never decides whether something is malicious; that decision was already made deterministically in Step 4.

**Step 7 — Output**
The analyst sees one alert with a visual timeline of every linked step, the enrichment data, and the AI summary — instead of four to ten disconnected alerts they'd have to manually piece together. High-confidence incidents can optionally trigger a Snort/firewall block, gated behind human approval for anything destructive.

---

## 5. Correlation "Basket" Logic (Plain English)

Every basket is keyed on shared identity, not just keyword matches:

| Field | Why it links events |
|---|---|
| Hostname | Same machine = same potential attacker session |
| Username/SID | Same account being abused |
| Process GUID/parent chain | Proves one process spawned another |
| Source/Internal IP | Links network activity back to the host |
| Time window (e.g. 10 min) | Keeps unrelated old activity out of the basket |

A basket only becomes a **High Alert** once it matches a full predefined chain — not just one suspicious event. This is what makes your output fundamentally different from Splunk/Elastic's default behavior of one alert per rule hit.

---

## 6. Your GRC / Industry Profile Idea (Built In)

This solves real noise problems and is a genuine differentiator. Implementation:

- Tag every Sigma/MITRE rule with metadata: `industry: [finance, healthcare, saas, manufacturing]`, `framework: [pci-dss, hipaa, soc2, gdpr]`.
- Store a per-client YAML profile, e.g.:

```yaml
client: "ExampleHospitalCo"
industry: healthcare
frameworks: [hipaa]
enabled_rule_groups:
  - active_directory
  - email
  - endpoint
  - database_access     # PHI access is critical here
disabled_rule_groups:
  - pci_cardholder_data  # not relevant, reduces noise
alert_sensitivity: high
log_sources_available:
  - windows_event_logs
  - sysmon
  - dns
  - ad
```

- The correlation engine loads this profile at startup and only activates the relevant rule groups and sequence patterns for that deployment — no code changes, just config. This means one engine codebase can serve very different companies without flooding any of them with irrelevant alerts.

---

## 7. Tiered Alerting (Don't Wait for the Full Chain)

Waiting for the entire attack chain to complete before alerting is dangerous — it could mean a 5–10 minute head start for the attacker. The engine should alert progressively, at every stage of confidence, not just at the end.

### Tier 0 — Critical Single Event (instant, bypasses correlation entirely)
Some indicators are dangerous enough on their own and should never wait for basket-building:
- Hash matches a known ransomware/malware family (VirusTotal/MISP hit)
- Connection to a known C2 IP (MISP/AbuseIPDB high-confidence hit)
- Critical Sigma rule with `level: critical` (e.g. LSASS dump, disabling Windows Defender, mimikatz-pattern command line)

→ **Fires immediately as a High alert**, with a playbook attached (see below), no correlation required.

### Tier 1 — Single Suspicious Event (instant, low/medium confidence)
Any Sigma/YARA rule match on its own, even if not critical (e.g. encoded PowerShell, unusual logon time, AD privilege change).

→ Fires immediately as a **Low/Medium alert** and simultaneously opens a new basket tagged to that host/user, so it's ready to absorb related events if they follow.

### Tier 2 — Partial Chain Match (rising confidence, live updates)
As more events land in an existing basket, its confidence score increases and the alert escalates in place (not a new alert — the same incident gets updated).

**Confidence scoring (simple, transparent — not a black box):**

```
confidence = (matched_stages / total_stages_in_pattern) * 100

Example — 4-stage chain (Initial Access → Execution → Persistence → C2):
  1 stage matched  → 25%  → Low
  2 stages matched → 50%  → Medium
  3 stages matched → 75%  → High
  4 stages matched → 100% → Critical / Confirmed Incident
```

Each jump in confidence re-triggers a notification so the analyst sees the incident "growing" in real time rather than discovering it cold at 100%.

### Tier 3 — Full Chain Match (Critical, confirmed incident)
Full predefined sequence matched → Critical alert, full AI narrative, enrichment, and (optionally) auto-response.

---

## 8. Playbook Concept (Action, Not Just Alerting)

Every alert tier and every MITRE technique should map to a **predefined playbook** — a set of recommended or automated next steps, so the system doesn't just say "something is wrong," it says "here's what to do about it." This is the SOAR layer of your project (TheHive + your own playbook engine).

**Playbook structure (config-driven, like the GRC profiles):**

```yaml
playbook: "powershell_encoded_command"
trigger_tier: 1
matched_technique: T1059.001
actions:
  - type: notify
    target: soc_email / soc_chat_webhook
    severity: medium
  - type: enrich
    targets: [process_hash, parent_process]
  - type: recommend
    text: "Review parent process tree. If unrecognized, isolate host pending review."
  - type: auto_response
    enabled: false   # human approval required at this tier
---
playbook: "confirmed_c2_ransomware_chain"
trigger_tier: 3
matched_technique: [T1059.001, T1053.005, T1071]
actions:
  - type: notify
    target: soc_email / soc_chat_webhook / on_call_pager
    severity: critical
  - type: auto_response
    enabled: true        # can be auto-triggered at this tier
    steps:
      - isolate_host (EDR API or network ACL)
      - block_ip (Snort/firewall)
      - create_thehive_case
  - type: human_approval_required: false   # only for the most critical, pre-approved chains
```

This gives you three tiers of response automation:
- **Notify only** (Tier 0/1) — analyst decides everything.
- **Notify + recommend + enrich** (Tier 2) — analyst gets a head start, still decides.
- **Notify + auto-contain** (Tier 3, only for pre-approved critical chains) — system acts, analyst reviews after.

You control per-client (via the GRC profile) whether Tier 3 auto-response is even allowed — some clients will never want automatic isolation/blocking, others will.

---

## 9. GRC / Compliance Layer — Full Perspective

Doing this "properly" means treating it as more than just an on/off rule switch. A complete compliance layer needs to cover four separate dimensions:

### 9.1 Regulatory Mapping (which rules matter for which framework)
Each rule and playbook should carry compliance tags so you can prove coverage during an audit:

```yaml
rule: "unauthorized_phi_database_access"
frameworks_covered: [hipaa]
control_reference: "HIPAA §164.312(b) - Audit Controls"
```

This lets you generate a **compliance coverage report** per client: "Here are the 40 controls required by HIPAA, here are the 38 we actively monitor, here are the 2 gaps and why (e.g. log source not available)." This is something almost no open-source tool offers out of the box and is a real selling point to companies that need audit evidence.

### 9.2 Data Handling & Retention (compliance isn't just detection)
Different frameworks mandate different log retention periods and access controls:
- HIPAA: minimum 6 years retention for audit logs
- PCI-DSS: minimum 1 year, 3 months immediately available
- GDPR: data minimization — don't store more personal data in logs than necessary, and support "right to erasure" requests

→ Your Elasticsearch ILM (Index Lifecycle Management) policies should be configurable per client profile, not hardcoded. Add a `retention_days` and `pii_redaction: true/false` field to the GRC profile.

### 9.3 Access Control & Segregation (who can see what)
If you ever host multiple clients (multi-tenant), GRC also means client A's SOC dashboard must never show client B's data. Even single-tenant, role-based access (Analyst vs Admin vs Auditor read-only) should exist from day one — auditors will ask for this specifically.

### 9.4 Evidence & Auditability (proving the system works)
For every alert, the system should retain:
- Which rule/playbook fired and its exact version
- What data was used to make the decision (the raw events in the basket)
- Who took action and when (if a human approved a response)

This audit trail is what turns "we have a detection system" into "we have a system that satisfies SOC2/HIPAA/PCI evidence requirements" — which is the sentence that actually gets budget approved in a real company.

**Updated GRC profile, combining all four dimensions:**

```yaml
client: "ExampleHospitalCo"
industry: healthcare
frameworks: [hipaa]
enabled_rule_groups: [active_directory, email, endpoint, database_access]
disabled_rule_groups: [pci_cardholder_data]
alert_sensitivity: high
auto_response_allowed: false        # Tier 3 auto-contain disabled for this client
retention_days: 2190                # 6 years per HIPAA
pii_redaction: true
access_roles: [analyst, admin, auditor_readonly]
log_sources_available: [windows_event_logs, sysmon, dns, ad, database_logs]
```

---

## 10. Critical Engineering Gaps (Must-Fix Before MVP Works Reliably)

These aren't optional polish — without them the engine will either burn through API quotas, lose data on restart, flood the dashboard with noise, or annoy analysts into ignoring it entirely.

### 10.1 Enrichment Caching (protects free API quotas)
VirusTotal (~500/day), AbuseIPDB, and URLhaus all have strict free-tier limits. A single incident basket can easily contain 10+ unique IPs/hashes, burning through your daily quota in one simulated attack.

**Fix — Enrichment Cache Layer:**
- Before calling any external API, check PostgreSQL (or Redis with a TTL) for a cached result on that exact IP/hash/domain.
- If cached within the last 24 hours, return the cached verdict — skip the API call.
- Only call the live API on a cache miss or expiry.

```sql
enrichment_cache(
  indicator TEXT,        -- IP, hash, or domain
  indicator_type TEXT,   -- ip | hash | domain
  source TEXT,           -- virustotal | abuseipdb | urlhaus
  verdict JSONB,
  checked_at TIMESTAMP
)
```
This alone cuts external API usage by roughly 90% in practice, since the same C2 IPs and hashes tend to reappear across baskets and across test runs.

### 10.2 Basket Persistence (restart-proofing)
Redis is in-memory only. If the Python correlation engine crashes or restarts mid-attack, every active basket is lost — and a chain that was 75% complete silently vanishes instead of ever reaching a confirmed alert.

**Fix — PostgreSQL as source of truth, Redis as fast cache:**
- Every new basket and every event appended to it is written to PostgreSQL immediately (not just Redis).
- Redis holds the same data for fast reads/writes during active correlation, but it's disposable.
- On engine startup, reload all baskets with `status = 'open'` from PostgreSQL back into Redis before resuming correlation. The engine becomes restart-safe with zero lost incidents.

### 10.3 Tier 0/1 Deduplication (prevents alert storms)
A single piece of malware can trigger the same Sigma rule dozens of times in seconds (e.g. 50 registry persistence keys in 2 seconds). Without dedup, that's 50 separate "instant High alerts" flooding the dashboard — which is exactly the alert-fatigue problem you're trying to solve, just self-inflicted.

**Fix — Deduplication window:**
- Key: `(hostname + indicator + rule_id)`.
- If an identical key fires again within a configurable window (default 5 minutes), don't create a new alert — increment a `occurrence_count` on the existing one and refresh its `last_seen` timestamp.
- The dashboard shows "Encoded PowerShell on DESKTOP-JOHN-01 ×47" instead of 47 separate rows.

### 10.4 False-Positive Feedback Loop (the "learning" gap)
Without this, the same benign-but-noisy pattern fires again every day forever, and analysts eventually stop trusting (and stop checking) the tool — which kills adoption.

**Fix — Silencing rules tied to the GRC profile:**
- When an analyst marks an incident "False Positive" / "Benign" in TheHive, the engine writes a temporary suppression rule: `host + user + rule_id → suppressed until [now + 7 days]` (duration configurable per client).
- The correlation engine checks this suppression table before firing future alerts on that exact combination.
- Suppressions should be visible and reversible by an admin (not silent forever) — an auditor will ask why a rule went quiet, so log who created the suppression and when it expires.

```sql
alert_suppression(
  hostname TEXT,
  username TEXT,
  rule_id TEXT,
  suppressed_by TEXT,     -- analyst who marked it FP
  suppressed_at TIMESTAMP,
  expires_at TIMESTAMP
)
```

This is genuinely what separates a toy detection script from a "mature" SOC platform — the system gets quieter and smarter over time instead of repeating the same mistakes.

---

## 11. What Makes This Stand Out in the Market

- **Pre-investigated alerts, not raw alerts** — closes the "L1 ceiling" gap most AI-SOC tools stop at.
- **Deterministic correlation first, AI narrates second** — avoids the "black box AI" trust problem.
- **Configurable GRC/industry profiles** — undercuts paid SIEM "content packs" that vendors charge extra for.
- **Confidence scoring per incident** (consider adding) — lets analysts triage by severity instead of treating every alert equally.
- **Explainability log** — show exactly which rule and which basket steps fired, so it's auditable.
- **Fully self-hostable on free/open-source tools** — $0 licensing cost is a real selling point for SMBs who can't afford Splunk ES or XSOAR.

---

## 12. MVP Reality-Check Gotchas (Fix These or the Demo Will Fail)

These are the kind of problems that don't show up until you actually run the system — better to design around them now than debug them at 2am before a demo.

### 12.1 Time Synchronization (The Silent Basket Killer)
If endpoint clocks drift even by a few minutes, events can arrive "out of order" relative to real attack time, and your sequence matcher will fail to link them — the basket just never completes.

**Fix:**
- Don't correlate on the log's own embedded timestamp (`log.event_time`/endpoint clock). Correlate on the **ingestion timestamp** — the time Logstash/Elasticsearch actually received the event (`@timestamp`). This guarantees consistent ordering regardless of whether an endpoint's clock is wrong.
- As a longer-term hygiene fix, enforce NTP/Chrony time sync on all endpoints feeding the system.

### 12.2 ECS Normalization Is the Real Time Sink
Writing perfect Grok/Mutate parsers to map every log type (Sysmon, Zeek, Windows Event Logs, O365, firewall, etc.) into one common schema is, realistically, weeks of regex work — easily the most underestimated task in the whole build.

**Fix (MVP scope):**
- Don't normalize everything for the MVP. Use **Sysmon** and **Zeek** only — both already have mature, community-built ECS pipelines available, so you're not writing parsers from scratch.
- Hardcode the correlation engine to expect these two JSON formats first. Prove the correlation logic works end-to-end, *then* expand to additional log sources one at a time.

### 12.3 Don't Build Generic EDR/Firewall Action APIs Yet
A playbook step like "isolate host via EDR API" sounds simple but actually means writing and maintaining separate integrations for CrowdStrike, Defender, SentinelOne, Palo Alto, etc. — that's a multi-engineer, ongoing maintenance burden, not an MVP task.

**Fix (MVP scope):**
- Skip auto-isolation entirely for now. Implement only simple, local network blocking — e.g. a Python script that appends a deny rule to `iptables`/`hosts.deny` for a malicious IP.
- For host isolation, the playbook should output a clear manual instruction: *"Manual action required: isolate host [X] via your EDR console."* Prove the detection and correlation logic is reliable first; automate remediation as a later phase once you know what EDR(s) you're actually integrating with.

### 12.4 Resource Load — Don't Run Everything at Once Locally
Elasticsearch, Ollama, and (previously) Cuckoo together will overwhelm a single laptop if run simultaneously.

**Fix (MVP scope):**
- **Sandbox decision (per your update):** skip sandboxing entirely for the MVP. File attachments are handled by hash lookup against VirusTotal/Hybrid Analysis only — no local sandbox VM, no extra CPU load. This also removes one of the heaviest resource consumers from the stack entirely, which works in your favor here.
- **AI model size:** start with a small local model (Phi-3 or TinyLlama, ~2–3GB) instead of full Llama 3 (8–12GB) for narrative generation. It's good enough to prove the RAG pipeline works. Upgrade to a larger model later once you move to a cloud VM with more RAM.
- If your laptop still struggles, run Elasticsearch + Ollama at different times during development rather than always-on simultaneously, or move early testing to a free-tier cloud VM.

---



## 13. Suggested Build Order (MVP First)

1. Stand up Elasticsearch + Logstash + Filebeat with one log source (Sysmon).
2. Add Zeek for network logs.
3. Build the Python correlation engine with one hardcoded attack chain (Logon → PowerShell → Persistence → C2), correlating on ingestion timestamp.
4. Add VirusTotal + AbuseIPDB enrichment, with the caching layer from Section 10.1 built in from day one.
5. Add MISP for your own intel store.
6. Add Ollama (small model first) + ChromaDB + LangChain for the narrative layer.
7. Build the GRC profile loader (YAML-based) and the basket persistence layer (Section 10.2).
8. Add the simple iptables/hosts.deny blocking script for the response layer.
9. Build the dashboard (start with Kibana, move to React later).
10. Use Atomic Red Team to simulate attacks and validate the full chain end-to-end.
