"""
ai/narrator.py
--------------
Phase 4: Generates plain-English incident narratives using a local LLM via Ollama and ChromaDB RAG.

Requirements:
    pip install langchain-community chromadb ollama
"""
import os
import json
from soc_engine.config.settings import settings

# LangChain community components
from langchain_community.llms import Ollama
from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import OllamaEmbeddings

VECTOR_DB_DIR = "./chromadb_store"


def get_fallback_narrative(basket: dict, matched_chain: dict) -> str:
    """Generates a standard templated narrative when LLM/RAG is offline."""
    host = basket.get("host_name", "UNKNOWN")
    user = basket.get("user_name", "UNKNOWN")
    confidence = basket.get("confidence_score", 0)
    chain_name = matched_chain.get("name", "Unknown Chain")
    stages = basket.get("matched_stages", [])

    stage_summary = ", ".join(
        f"Stage {s.get('stage')} ({s.get('mitre')})" for s in stages
    )

    # Fallback template
    narrative = (
        f"**Attack Summary**: An attack chain matching '{chain_name}' was detected "
        f"on host '{host}' for user '{user}' with {confidence}% confidence. "
        f"The following stages were observed: {stage_summary}.\n\n"
        f"**Likely Objective**: Based on the MITRE techniques observed, this activity "
        f"is consistent with an attacker establishing a foothold and preparing for "
        f"data exfiltration or lateral movement.\n\n"
        f"**Immediate Actions**:\n"
        f"- Isolate host '{host}' from the network.\n"
        f"- Reset credentials for user '{user}'.\n"
        f"- Review scheduled tasks and registry run keys on the affected host."
    )
    return narrative


def generate_incident_narrative(
    basket: dict,
    enrichment: dict,
    matched_chain: dict,
) -> str:
    """
    Generates a 3-paragraph plain-English incident summary.
    Attempts to fetch context from ChromaDB RAG and uses Ollama local LLM.
    Falls back gracefully to a templated summary if Ollama/RAG is unreachable.
    """
    host = basket.get("host_name", "UNKNOWN")
    user = basket.get("user_name", "UNKNOWN")
    source_ip = basket.get("source_ip", "UNKNOWN")
    confidence = basket.get("confidence_score", 0)
    chain_name = matched_chain.get("name", "Unknown Chain")
    stages = basket.get("matched_stages", [])

    # 1. RAG: Retrieve MITRE descriptions from ChromaDB
    mitre_contexts = []
    vectorstore_loaded = False
    
    if os.path.exists(VECTOR_DB_DIR):
        try:
            embeddings = OllamaEmbeddings(
                model="nomic-embed-text",
                base_url=settings.OLLAMA_HOST
            )
            vectorstore = Chroma(
                persist_directory=VECTOR_DB_DIR,
                embedding_function=embeddings,
                collection_name="mitre_attack"
            )
            
            for s in stages:
                mitre_id = s.get("mitre")
                if mitre_id:
                    # Query Chroma using technique ID metadata filter
                    docs = vectorstore.similarity_search(
                        query=mitre_id,
                        k=1,
                        filter={"technique_id": mitre_id}
                    )
                    if docs:
                        mitre_contexts.append(docs[0].page_content)
            
            vectorstore_loaded = True
        except Exception as e:
            print(f"[!] RAG retrieval error: {e}. Falling back to default context.")

    # Format techniques list
    stages_context = ""
    for s in stages:
        stage_num = s.get("stage")
        mitre_id = s.get("mitre")
        evt_type = s.get("event", {}).get("rule_id", "Unknown event")
        stages_context += f"- Stage {stage_num}: Technique {mitre_id} triggered by {evt_type}\n"

    # Format threat intel enrichments
    enrichment_context = ""
    if enrichment:
        for indicator, sources in enrichment.items():
            enrichment_context += f"Indicator: {indicator}\n"
            for src, details in sources.items():
                if details and "error" not in details:
                    enrichment_context += f"  - {src.upper()}: {json.dumps(details)}\n"
                elif details:
                    enrichment_context += f"  - {src.upper()}: Error/Offline\n"
    else:
        enrichment_context = "No public threat intelligence indicators detected."

    mitre_text = "\n".join(mitre_contexts) if mitre_contexts else "No detailed MITRE ATT&CK technique descriptions found."

    # 2. Invoke local LLM via LangChain Ollama wrapper
    try:
        print(f"[*] Contacting Ollama service at {settings.OLLAMA_HOST} (model '{settings.OLLAMA_MODEL}')...")
        llm = Ollama(
            base_url=settings.OLLAMA_HOST,
            model=settings.OLLAMA_MODEL,
            timeout=15.0  # Set reasonable timeout
        )
        
        prompt = f"""
You are a senior SOC analyst assistant. Based on the following incident data and MITRE technique details, write an incident narrative.

Your narrative MUST contain exactly three sections:
1. **Attack Summary**: A 3-sentence plain-English summary of what the attacker did and how.
2. **Likely Objective**: The likely attack objective (ransomware, data theft, lateral movement, persistence, or command & control).
3. **Immediate Actions**: A list of up to 3 immediate recommended containment actions.

Be concise. Do not repeat raw JSON. Write for a junior SOC analyst.

Incident Data:
- Host: {host}
- User: {user}
- Source IP: {source_ip}
- Attack Chain Matched: {chain_name}
- Confidence Score: {confidence}%
- Matched Stages:
{stages_context}
- Enrichment Information:
{enrichment_context}

MITRE ATT&CK Technique Context:
{mitre_text}

Write the narrative now:
"""
        response = llm.invoke(prompt)
        print("[+] AI narrative generated successfully.")
        return response.strip()

    except Exception as e:
        print(f"[!] AI narrative generation failed: {e}. Falling back to standard template.")
        return get_fallback_narrative(basket, matched_chain)
