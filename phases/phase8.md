# Phase 8 — Log Analysis & Elastic Integration

## Overview

Phase 8 implements a comprehensive Log Analysis interface directly within the SOC dashboard. It allows analysts to perform rapid log searches, use pre-built queries, save searches for later use, and enrich indicators on-demand—all without leaving the LogXPro platform.

---

## What Was Built

### 1. Database Updates (`database/init.sql`)
- Added `saved_searches` table to persist analyst queries.
- Created `ensure_saved_searches_table()` in `soc_engine/api_server.py` to automatically apply the schema migration on startup.

### 2. Backend API Endpoints (`soc_engine/api_server.py`)
- **`GET /api/logs/search`**: Main search endpoint. Connects directly to the `soc-alerts` index in Elasticsearch, wrapping Lucene syntax queries with time bounds (`_from`) and `host` filters. Includes a mock fallback mechanism if ES is unreachable.
- **`GET /api/logs/saved_searches`**: Retrieves all saved searches from PostgreSQL.
- **`POST /api/logs/saved_searches`**: Stores a new saved search.
- **`DELETE /api/logs/saved_searches/{id}`**: Removes a saved search.
- **`GET /api/enrichment/{indicator}`**: Connects to the existing `orchestrator.py` logic to trigger on-demand enrichment for IPs, domains, or hashes.

### 3. Frontend Service Updates (`frontend/src/api.js`)
- Added service wrapper functions: `searchLogs`, `fetchSavedSearches`, `saveSearch`, `deleteSavedSearch`, `enrichIndicator`.

### 4. Log Analysis Page (`frontend/src/pages/LogAnalysisPage.jsx`)
- **Search Bar**: Fully supports Lucene query string syntax.
- **Shortcut Bar**: One-click quick filters (e.g., "High/Critical Events", "Failed Logons", "PowerShell Executions").
- **Saved Searches**: Analysts can save complex queries. Saved searches appear as clickable tags that immediately re-run the query.
- **Results Table**: Clean tabular view of events with severity badges and timestamps.
- **Side Panel (Event Details)**:
  - Displays formatted raw JSON.
  - Automatically extracts IP addresses and hashes from the raw JSON payload.
  - Provides a "Run Enrichment" button for each extracted indicator, leveraging the new backend endpoint to pull VirusTotal, AbuseIPDB, and MISP data on demand.

### 5. Routing (`frontend/src/App.jsx`)
- Added `/logs` route and integrated the "Log Analysis" tab into the main application sidebar using the `Terminal` Lucide icon.

---

## Verification
- **API Endpoints**: Successfully verified using `Invoke-RestMethod`. Endpoint gracefully handles both live DB access and mock fallbacks.
- **Frontend**: Navigation, search shortcuts, and saved searches are fully operational. On-demand enrichment successfully extracts and enriches data via mock/live handlers.

---

## Technical Notes
- The search endpoint uses `query_string` logic in Elasticsearch, meaning analysts can leverage powerful operators like `AND`, `OR`, wildcards, and field-specific matches (e.g., `event_type:"Process Creation"`).
- The "Run Enrichment" feature parses nested JSON to find IPv4 addresses (excluding local subnets) and MD5/SHA1/SHA256 hashes, enabling rapid threat context gathering directly from the raw log without waiting for an alert basket to form.
