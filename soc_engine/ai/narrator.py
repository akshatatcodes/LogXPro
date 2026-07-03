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
                        desc = docs[0].page_content
                        # Truncate to the first 3 sentences of the actual description to prevent prompt bloat
                        desc_parts = desc.split("Description:", 1)
                        if len(desc_parts) == 2:
                            header = desc_parts[0].strip() + "\nDescription:"
                            body = desc_parts[1].strip()
                            import re
                            sentences = re.split(r'(?<=[.!?])\s+', body)
                            truncated_body = " ".join(sentences[:3]) if len(sentences) > 3 else body
                            mitre_contexts.append(f"{header} {truncated_body}")
                        else:
                            import re
                            sentences = re.split(r'(?<=[.!?])\s+', desc.strip())
                            truncated = " ".join(sentences[:3]) if len(sentences) > 3 else desc
                            mitre_contexts.append(truncated)
            
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

    # 2. Determine likely objective and immediate actions deterministically to avoid hallucinations
    chain_id = matched_chain.get("chain_id", "")
    chain_name_lower = chain_name.lower()

    if chain_id == "chain_001" or "phishing" in chain_name_lower or "c2" in chain_name_lower:
        likely_objective = "Command & Control"
        actions = [
            f"Isolate the affected host '{host}' from the network to block C2 communications.",
            f"Reset credentials for the compromised user account '{user}' and terminate all active sessions.",
            f"Audit process logs on '{host}' to identify persistent scheduled tasks or registry keys."
        ]
    elif chain_id == "chain_002" or "lateral" in chain_name_lower or "credential" in chain_name_lower:
        likely_objective = "Lateral Movement / Credential Theft"
        actions = [
            f"Isolate host '{host}' and any secondary target systems from the network.",
            f"Reset credentials for the administrative user '{user}' across the domain/local environment.",
            f"Review process execution logs for credential dumping tools (e.g., Mimikatz) or WMI parent-child anomalies."
        ]
    elif chain_id == "chain_003" or "ransomware" in chain_name_lower or "recovery" in chain_name_lower:
        likely_objective = "Ransomware / Data Destruction"
        actions = [
            f"Isolate the host '{host}' immediately to stop the spread of file encryption.",
            f"Identify and terminate the ransomware processes/services (e.g., VSS deletion helper or shadow copy wiper).",
            f"Verify the status of volume shadow copies and retrieve clean system/data backups."
        ]
    else:
        likely_objective = "Intrusion / Attempted Compromise"
        actions = [
            f"Isolate host '{host}' from the network.",
            f"Reset credentials for user '{user}'.",
            f"Review security logs on '{host}' to locate the intrusion vector."
        ]

    # 3. Invoke local LLM via LangChain Ollama wrapper to get a 3-sentence attack summary
    try:
        print(f"[*] Contacting Ollama service at {settings.OLLAMA_HOST} (model '{settings.OLLAMA_MODEL}')...")
        llm = Ollama(
            base_url=settings.OLLAMA_HOST,
            model=settings.OLLAMA_MODEL,
            timeout=15.0  # Set reasonable timeout
        )
        
        prompt = f"""<|system|>
You are a senior SOC analyst. Write a concise, 3-sentence attack summary in plain English explaining what the attacker did on the system based on the provided incident data and MITRE context.
Do not write any preamble, conversational filler, introductory words, or other sections. Start the summary immediately.
<|user|>
Incident Data:
- Host: {host}
- User: {user}
- Attack Chain Matched: {chain_name}
- Matched Stages:
{stages_context}

MITRE ATT&CK Context:
{mitre_text}

Write the 3-sentence attack summary now:
<|assistant|>
"""
        response = llm.invoke(prompt)
        print("[+] AI narrative generated successfully.")
        llm_summary = response.strip()
        
        # Clean any leading headers if the model printed them
        for header in ["**Attack Summary**:", "Attack Summary:", "Summary:", "Incident Summary:", "Incident Data:"]:
            if llm_summary.startswith(header):
                llm_summary = llm_summary[len(header):].strip()
        
        # Filter out lines echoing the input prompt format
        lines = [line.strip() for line in llm_summary.split("\n")]
        cleaned_lines = []
        for line in lines:
            if not line:
                continue
            line_lower = line.lower()
            if any(line_lower.startswith(prefix) for prefix in [
                "- host:", "- user:", "- source ip:", "- attack chain:", 
                "- confidence:", "- matched stages:", "mitre attack context:", 
                "technique id:", "name:", "description:", "generate the narrative:",
                "incident data:", "matched stage(s):", "threat intel:", "enrichment information:"
            ]):
                continue
            cleaned_lines.append(line)
        
        llm_summary = " ".join(cleaned_lines).strip()
        
        # Fallback summary if it's empty or too short / garbage
        if len(llm_summary) < 30:
            stage_list = ", ".join(s.get("mitre", "Unknown Technique") for s in stages if s.get("mitre"))
            llm_summary = (
                f"An attack matching the '{chain_name}' pattern was detected on host '{host}' "
                f"for user '{user}'. The activity involved multiple matching stages, specifically "
                f"techniques: {stage_list}."
            )
        
        # Assemble the formatted narrative
        formatted_narrative = (
            f"**Attack Summary**: {llm_summary}\n\n"
            f"**Likely Objective**: {likely_objective}\n\n"
            f"**Immediate Actions**:\n" + "\n".join(f"- {act}" for act in actions)
        )
        return formatted_narrative

    except Exception as e:
        print(f"[!] AI narrative generation failed: {e}. Falling back to standard template.")
        return get_fallback_narrative(basket, matched_chain)
