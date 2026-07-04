# Phase 9 — Case Writing & Escalation

## Overview
Phase 9 adds a formalized incident case management system to the LogXPro dashboard. Analysts can now escalate raw alert baskets directly into structured cases, track investigation progress, and maintain a historical record of significant security incidents.

## What Was Built

### 1. Database Schema
- Added the `cases` table to PostgreSQL via `init.sql` and the FastAPI `lifespan` automatic migration. 
- Tracks case attributes: Title, Severity, Assignee, Executive Summary, Technical Details, Status, and associated `basket_id`.

### 2. Backend API (`soc_engine/api_server.py`)
- **GET /api/cases**: Retrieves all formalized cases from the database in descending order of creation.
- **POST /api/cases**: Creates a new case and natively supports auto-closing the linked `incident_basket` (so analysts don't need to close the alert queue item separately).

### 3. Frontend Pages
- **CasesPage.jsx**: A beautiful overview table mirroring the design language of the Alert Queue. Shows Severity badges, Case IDs, Assignees, and an Open/Closed status tracker.
- **CaseEscalatePage.jsx**: An escalation form built using React Hook Form & Tailwind. Natively supports pulling state from the React Router `useLocation` hook, allowing it to pre-populate the Title, Severity, Assignee, and Technical Details (JSON context) straight from an alert in the queue.

### 4. Integration
- Replaced the mockup "Escalate to Case" button in `AlertQueuePage.jsx` with real routing logic that passes the full alert object into the new `CaseEscalatePage` form.
- Added a new `Case Reports` icon (`FileText`) to the global sidebar navigation.

## Verification
- API tested successfully via PowerShell `Invoke-RestMethod` and confirmed DB inserts.
- Frontend forms hooked up via Tanstack React Query for immediate cache invalidation and seamless redirection after case submission.
