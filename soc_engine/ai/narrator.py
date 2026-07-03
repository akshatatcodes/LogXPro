"""
ai/narrator.py
--------------
Phase 4: Generates plain-English incident narratives using a local LLM via Ollama.

Requirements (Phase 4):
    pip install langchain-community chromadb ollama

Local LLM Setup:
    1. Install Ollama: https://ollama.ai
    2. Pull a model: ollama pull phi3
    3. Ensure OLLAMA_HOST is set in settings (default: http://localhost:11434)
"""
import json
from soc_engine.config.settings import settings

# Phase 4 stub — dependencies not yet installed
# Uncomment when starting Phase 4:
#
# from langchain_community.llms import Ollama
# from langchain_community.vectorstores import Chroma
# from langchain.chains import RetrievalQA
# from langchain_community.embeddings import OllamaEmbeddings


def generate_incident_narrative(
    basket: dict,
    enrichment: dict,
    matched_chain: dict,
) -> str:
    """
    Generates a 3-paragraph plain-English incident summary.

    Phase 4 NOTE: This stub returns a templated summary.
    Replace with the LangChain + ChromaDB + Ollama implementation
    when Phase 4 begins.

    Args:
        basket:        Basket dict with matched_stages and confidence_score.
        enrichment:    Enrichment results from Phase 3.
        matched_chain: Chain definition dict.

    Returns:
        Plain-English narrative string.
    """
    host = basket.get("host_name", "UNKNOWN")
    user = basket.get("user_name", "UNKNOWN")
    confidence = basket.get("confidence_score", 0)
    chain_name = matched_chain.get("name", "Unknown Chain")
    stages = basket.get("matched_stages", [])

    stage_summary = ", ".join(
        f"Stage {s['stage']} ({s['mitre']})" for s in stages
    )

    # Basic templated narrative (pre-LLM)
    narrative = (
        f"**Attack Summary**: An attack chain matching '{chain_name}' was detected "
        f"on host '{host}' for user '{user}' with {confidence}% confidence. "
        f"The following stages were observed: {stage_summary}.\n\n"
        f"**Likely Objective**: Based on the MITRE techniques observed, this activity "
        f"is consistent with an attacker establishing a foothold and preparing for "
        f"data exfiltration or lateral movement.\n\n"
        f"**Immediate Actions**: (1) Isolate host '{host}' from the network. "
        f"(2) Reset credentials for user '{user}'. "
        f"(3) Review scheduled tasks and registry run keys on the affected host."
    )

    return narrative


def build_llm_narrative(
    basket: dict,
    enrichment: dict,
    matched_chain: dict,
) -> str:
    """
    Phase 4 full implementation: LangChain + ChromaDB RAG + Ollama LLM.

    Activate this function by installing Phase 4 dependencies and replacing
    generate_incident_narrative() above.
    """
    raise NotImplementedError(
        "Phase 4 LLM narrative not yet activated. "
        "Run: pip install langchain-community chromadb ollama"
    )
