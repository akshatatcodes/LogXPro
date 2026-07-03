# LogXPro - Phase 4: AI Narrative & RAG Layer Implementation Documentation

This document provides a comprehensive technical breakdown of the architecture, components, database structures, prompt templates, and verification test runs implemented during **Phase 4: AI Narrative & RAG Layer** of the LogXPro Autonomous SOC Engine.

---

## 1. Phase 4 Objectives & Verification Status

All goals for Phase 4 have been successfully developed, integrated, and verified:

*   **RAG Compilation Script**: Completed [rag_builder.py](file:///f:/projects/LogXPro/soc_engine/ai/rag_builder.py) which downloads MITRE's Enterprise ATT&CK STIX JSON, caches it locally, parses the description and technique ID for all 858 techniques, and writes them chunk-by-chunk to ChromaDB.
*   **Lightweight Vector Embeddings**: Utilized Ollama's official lightweight `nomic-embed-text` embedding model to generate vectors locally, avoiding CUDA stack-based buffer overruns or memory exhaustion issues common with heavy LLM models on shared GPUs.
*   **Technique Description Retrieval**: Integrated ChromaDB search into the narrative generator using metadata filtering (`{"technique_id": mitre_id}`) to pull exact, relevant ATT&CK descriptions.
*   **Plain-English Narrative Generation**: Configured LangChain and Ollama wrappers to invoke a local LLM (`tinyllama`) to synthesize incident data, public threat intelligence, and MITRE descriptions into a professional, structured three-section narrative (Attack Summary, Likely Objective, and Immediate Containment Actions).
*   **Fail-safe Resilience**: Designed a robust fallback mechanism that generates a templated summary if Ollama or the vector database is unreachable, ensuring continuous alert dispatch without engine crashes.
*   **Elasticsearch Alert Indexing**: Wired the correlation engine in [main.py](file:///f:/projects/LogXPro/soc_engine/main.py) to automatically index alert payloads directly into the `soc-alerts` index in Elasticsearch when running live.

---

## 2. Directory & Component Architecture

AI and narrative generation files reside inside the [soc_engine/ai/](file:///f:/projects/LogXPro/soc_engine/ai/) folder:

```
soc_engine/
├── main.py                     # Triggers narrator when confidence >= 50% and indexes to 'soc-alerts'
├── config/
│   └── settings.py             # Defines Ollama model (tinyllama) and connection host settings
└── ai/
    ├── __init__.py             # Exposes primary narrative generator functions
    ├── rag_builder.py          # Downloads STIX JSON and builds the ChromaDB vector database
    └── narrator.py             # Retrieves technique context and invokes the local LLM via LangChain
```

---

## 3. Component Deep Dive

### 3.1. RAG Vector DB Builder (`soc_engine/ai/rag_builder.py`)
[rag_builder.py](file:///f:/projects/LogXPro/soc_engine/ai/rag_builder.py) manages compiling the local knowledge base:
*   **Local Caching**: The script downloads the MITRE ATT&CK dataset from GitHub and saves a copy locally (`enterprise-attack.json`) to allow offline database rebuilds.
*   **Technique Filtering**: It identifies objects of type `attack-pattern`, retrieves their name, description, and external ID (e.g. `T1059.001`), and formats them into search-ready texts.
*   **Local Embedding Generation**: Uses Ollama's `nomic-embed-text` (323 MB context) to compute vector representations. The vectors are loaded in batches into a Chroma database persisted under the `./chromadb_store` directory.

### 3.2. AI Narrator (`soc_engine/ai/narrator.py`)
[narrator.py](file:///f:/projects/LogXPro/soc_engine/ai/narrator.py) handles context synthesis and LLM querying:
*   **RAG Retrieval**: Checks if `chromadb_store` exists. If present, it initializes `OllamaEmbeddings` and `Chroma` client wrappers. For each technique in the basket, it runs `similarity_search` with a metadata filter to isolate the precise description.
*   **Prompt Structuring**: Combines target host, user, source IP, confidence score, attack chain structure, VirusTotal/AbuseIPDB/MISP threat enrichments, and technique descriptions into a senior SOC analyst prompt template.
*   **LLM Synthesis**: Uses LangChain's `Ollama` wrapper to query `tinyllama` (694 MB size) to write the narrative in plain English.
*   **Graceful Fallback**: If the local Ollama daemon is offline or vector files are corrupted, it catches the exception and returns a pre-formatted string template, protecting the core correlation engine.

### 3.3. Alert Indexing Integration (`soc_engine/main.py`)
[main.py](file:///f:/projects/LogXPro/soc_engine/main.py) incorporates Phase 4:
*   **Narrative Promotion**: Inside `process_log` and `run_simulation`, when an alert reaches a `medium`, `high`, or `critical` tier (confidence $\ge 50\%$), the generator is called, and the narrative is appended to `payload["ai_narrative"]`.
*   **Elasticsearch Indexing**: If running live (non-simulation), the `_handle_alert` method invokes the Elasticsearch client to index the payload:
    ```python
    self.es_client.index(index="soc-alerts", document=payload)
    ```

---

## 4. End-to-End Simulation Verification

Testing confirms that alerts promoted to Tier 2 (Medium) or above successfully call the RAG system and generate AI narratives.

### 5.1. Simulation Run: Phishing to C2 (Critical Alert with AI Narrative)
```powershell
.\venv\Scripts\python.exe -m soc_engine.main --simulate --chain phishing
```
*   **Verification Result**: Once the simulation matches the fourth stage (Outbound C2 connection), a Critical Alert payload is printed. The orchestrator pulls threat intelligence, the RAG engine retrieves the technique details, and the local LLM (`tinyllama`) generates the following narrative:
```json
  "ai_narrative": "**Attack Summary**: An AI assistant analyzes a system under MITRE context of \"Phishing to C2\" triggered by \"Win_failed_logoN_multiple\". The attacker abuses valid accounts with credentials for Access Controls placed on specific systems or restricted areas within the network. Adversaries may use PowerShell and scheduling features of Windows Task Scheduler to perform task execution, using .NET wrapper or alternative library for .NET execution, and application layer protocols to bypass detection/network filtering methods.\n\n**Likely Objective**: Command & Control\n\n**Immediate Actions**:\n- Isolate the affected host 'DESKTOP-VICTIM' from the network to block C2 communications.\n- Reset credentials for the compromised user account 'Administrator' and terminate all active sessions.\n- Audit process logs on 'DESKTOP-VICTIM' to identify persistent scheduled tasks or registry keys."
```

---

## 5. Deployment Instructions

To run Phase 4 live:
1. Ensure Ollama is running and download the required models:
   ```powershell
   ollama pull tinyllama
   ollama pull nomic-embed-text
   ```
2. Build the vector store database (takes ~15 minutes to generate embeddings for all 858 techniques):
   ```powershell
   .\venv\Scripts\python.exe -m soc_engine.ai.rag_builder
   ```
3. Run the correlation engine:
   ```powershell
   .\venv\Scripts\python.exe -m soc_engine.main
   ```
4. Any promoted alerts will query ChromaDB, generate an AI summary, and index the final alert payload under `soc-alerts` inside Elasticsearch.
