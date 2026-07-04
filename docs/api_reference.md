# API Reference

The LogXPro backend is powered by FastAPI.

## Endpoints

### 1. Alert Queue
- `GET /api/alerts` - Returns paginated alerts from Elasticsearch/PostgreSQL.
- `GET /api/alerts/{id}` - Returns full details of a specific alert.
- `POST /api/alerts/{id}/assign` - Assigns the alert to an analyst.
- `POST /api/alerts/{id}/close` - Marks the alert as resolved.

### 2. Case Management
- `GET /api/cases` - List all formalized cases.
- `POST /api/cases` - Create a new case.

### 3. Log Analysis
- `GET /api/logs/search` - Proxy search into Elasticsearch.
- `GET /api/logs/saved_searches` - List saved analyst queries.
- `GET /api/enrichment/{indicator}` - On-demand threat intel enrichment.
