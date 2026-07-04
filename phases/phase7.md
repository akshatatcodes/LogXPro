# Phase 7 — Main Dashboard & Alert Queue

## Overview

Phase 7 delivers the central SOC dashboard and fully functional alert queue as a modern React + Vite single-page application (SPA). It wires up live data from the existing FastAPI backend through new REST endpoints and renders a premium, glassmorphic dark-mode interface.

---

## What Was Built

### 7.1 Backend API Endpoints (`soc_engine/api_server.py`)

All routes return rich JSON with database fallback to mock data when PostgreSQL or Elasticsearch is offline.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/dashboard/metrics` | Total alerts today, open baskets, confirmed incidents, FP rate, and hourly severity aggregates for the chart |
| `GET` | `/api/baskets/open` | All currently open (forming) incident baskets with confidence scores and matched MITRE stages |
| `GET` | `/api/alerts?page=&limit=&status=` | Paginated alert queue with optional status filter. Returns `{ alerts, total, page, limit, pages }` |
| `GET` | `/api/alerts/{basket_id}` | Full single-basket detail with events, enrichment (VT/AbuseIPDB/MISP), and AI narrative |
| `POST` | `/api/alerts/{basket_id}/assign` | Assign basket to a named analyst. Writes to `assigned_to` column and `audit_log` |
| `POST` | `/api/alerts/{basket_id}/close` | Close basket as resolved. Updates `status`, writes to `audit_log` |
| `POST` | `/api/alerts/{basket_id}/false-positive` | Mark as FP, extract rule context from matched stages, create 7-day suppression rule, write audit entry |
| `POST` | `/api/grc` | Dynamically switch active GRC profile (`default`/`finance`/`healthcare`) and reload on running engine |

#### Supporting Changes
- **`database/init.sql`**: Added `assigned_to TEXT` column to `incident_baskets` table.
- **Startup migration**: `ensure_assigned_to_column()` runs `ALTER TABLE … ADD COLUMN IF NOT EXISTS` on every API server startup so existing databases are automatically migrated.
- **Background engine exposure**: `background_engine` global allows GRC profile hot-reload on the running correlation thread without restarting.

---

### 7.2 Frontend Application (`frontend/`)

Built with: **React 18 + Vite 8 + Tailwind CSS v4 + Recharts + TanStack Query v5 + React Router v6**

#### Design System
- **Font**: Outfit (UI) + JetBrains Mono (code/IPs)
- **Color palette**: Curated dark cyber theme with CSS custom properties
- **Glassmorphism**: `glass-card` class with `backdrop-filter: blur(16px)`, translucent backgrounds, and soft borders
- **Severity colors**: Critical (#f43f5e) · High (#f97316) · Medium (#eab308) · Low (#06b6d4)
- **Animations**: `fadeInUp` on expanded panels, pulse ring on live indicator
- **Glow effects**: Purple/red/orange/cyan contextual glow shadows

#### File Structure
```
frontend/
├── src/
│   ├── main.jsx                 # React entry point
│   ├── App.jsx                  # Router + QueryClient + Sidebar layout
│   ├── index.css                # Design system: tokens, glassmorphism, badges, buttons, table, timeline
│   ├── api.js                   # Axios-based API service layer
│   ├── utils.js                 # Helpers: severityFromScore, formatTime, ANALYSTS list, MITRE labels
│   └── pages/
│       ├── DashboardPage.jsx    # Metrics + chart + open baskets feed
│       ├── AlertQueuePage.jsx   # Table + expandable row details + analyst actions
│       ├── SettingsPage.jsx     # GRC profile selector cards
│       └── CaseEscalatePage.jsx # Phase 9 escalation placeholder
├── index.html                   # SEO title + meta + font preconnects
├── vite.config.js               # Tailwind plugin + /api proxy → localhost:8000
└── package.json
```

---

### 7.3 Dashboard Page (`DashboardPage.jsx`)

**Metric Cards (4 at top)**:
| Card | Colour | Data Source |
|------|--------|-------------|
| Alerts Today | Red glow | `alerts_today` from `/api/dashboard/metrics` |
| Open Baskets | Purple glow | `open_baskets` from `/api/dashboard/metrics` |
| Confirmed Incidents | Green | `confirmed_incidents` |
| FP Rate | Cyan | `fp_rate` |

**Live Alert Severity Chart**:
- Stacked bar chart (Recharts `BarChart`) showing last 12 hours of alert activity
- X-axis: hour labels (`HH:00`)
- 4 bars per hour: low (cyan), medium (yellow), high (orange), critical (red)
- Custom dark-themed tooltip with coloured dots

**Active Basket Feed**:
- Shows all `status=open` baskets from `/api/baskets/open`
- Each card shows: circular SVG confidence ring (colour = severity), host + user + IP, MITRE stage tags, relative time
- Click → navigates to Alert Queue

---

### 7.4 Alert Queue Page (`AlertQueuePage.jsx`)

**Table Columns**:
`Severity` · `Host` · `User` · `Chain / MITRE` · `Confidence` · `Time` · `Assigned` · `Status`

**Confidence column**: Mini progress bar with severity-colour fill + percentage text.

**Expandable Rows**:
Each row click toggles an accordion panel containing:

1. **Kill Chain Timeline** — Numbered step cards with colour-coded severity rings, MITRE technique tags, timestamps, and command line/destination IP detail snippets. Built from basket events if available, or matched_stages otherwise.

2. **Threat Intelligence** — One `EnrichmentCard` per IP containing:
   - VirusTotal: `malicious / total` detections + country
   - AbuseIPDB: Abuse score `/100` + total reports
   - MISP: Found/not-found + threat actor tags

3. **AI Narrative** — Renders the AI-generated Markdown summary from the backend, with `**bold**` text rendered as `<strong>`.

4. **Actions Bar**:
   - **Assign to**: Dropdown of analyst names → `POST /api/alerts/{id}/assign`
   - **Close as Resolved**: `POST /api/alerts/{id}/close`
   - **Mark False Positive**: `POST /api/alerts/{id}/false-positive` (also creates suppression rule)
   - **Escalate to Case**: Navigates to `/cases/write` with the alert pre-filled in route state

All mutations invalidate the `['alerts']` React Query cache and show an inline success banner.

**Filters**: Text search (host/user/IP/basket ID), status dropdown filter. Paginated with numbered page buttons.

---

### 7.5 Settings Page (`SettingsPage.jsx`)

Three full-height profile selection cards:
- **Default SOC** — Purple, NIST/CIS
- **Finance / Banking** — Orange, PCI-DSS/SOX
- **Healthcare / HIPAA** — Green, HIPAA/HITECH

Selecting a profile calls `POST /api/grc { profile }`. The backend updates `settings.ACTIVE_GRC_PROFILE` and hot-reloads the profile on the running correlation engine. An active profile shows a checkmark badge and glow outline. A read-back panel shows the raw GRC YAML values loaded from disk.

---

### 7.6 Case Escalation (`CaseEscalatePage.jsx`)

Placeholder for Phase 9. Pre-fills case title (from host + severity), description (from AI narrative), severity dropdown, and analyst from the source alert's context. Submit button is disabled with a Phase 9 note.

---

## Running Phase 7

### Start FastAPI Backend
```bash
cd f:\projects\LogXPro
python -m soc_engine.api_server
# Runs on http://127.0.0.1:8000
```

### Start React Frontend
```bash
cd f:\projects\LogXPro\frontend
npm run dev
# Runs on http://localhost:3000
# API requests proxy to http://127.0.0.1:8000
```

### Production Build
```bash
cd f:\projects\LogXPro\frontend
npm run build
# Outputs optimised bundle to frontend/dist/
```

---

## Technical Notes

- **Fallback / Offline mode**: All backend endpoints return richly-formatted mock data if PostgreSQL or Elasticsearch is unreachable. The frontend is always functional for demo purposes.
- **React Query polling**: Metrics refresh every 20s, open baskets every 15s, alert queue every 30s automatically.
- **Audit trail**: Every analyst action (assign, close, FP) is written to the `audit_log` PostgreSQL table with actor name and detail JSON.
- **CORS**: Already enabled with `allow_origins=["*"]` in the FastAPI middleware.
- **Proxy**: Vite dev server proxies `/api/*` to `http://127.0.0.1:8000` so no CORS headers are needed during development.

---

## Files Changed / Created

| File | Action | Notes |
|------|--------|-------|
| `database/init.sql` | MODIFIED | Added `assigned_to TEXT` column |
| `soc_engine/api_server.py` | MODIFIED | 8 new Phase 7 endpoints + schema migration + GRC hot-reload |
| `frontend/` | NEW | Entire React application |
| `frontend/src/index.css` | NEW | Full design system |
| `frontend/src/App.jsx` | NEW | Router + sidebar + Query client |
| `frontend/src/api.js` | NEW | Axios API service layer |
| `frontend/src/utils.js` | NEW | Helpers + ANALYSTS + MITRE labels |
| `frontend/src/pages/DashboardPage.jsx` | NEW | Metrics + Recharts chart + basket feed |
| `frontend/src/pages/AlertQueuePage.jsx` | NEW | Full alert queue with expandable details |
| `frontend/src/pages/SettingsPage.jsx` | NEW | GRC profile selector |
| `frontend/src/pages/CaseEscalatePage.jsx` | NEW | Phase 9 escalation placeholder |
| `frontend/vite.config.js` | MODIFIED | Tailwind CSS v4 plugin + API proxy |
| `frontend/index.html` | MODIFIED | SEO title + meta description |
