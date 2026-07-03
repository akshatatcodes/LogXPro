"""
soc_engine/ai/rag_builder.py
----------------------------
Phase 4: Builds and populates the local ChromaDB vector store with MITRE ATT&CK data.
Can be executed from CLI:
    python -m soc_engine.ai.rag_builder
"""
import os
import json
import requests
import urllib3
import chromadb
from langchain_community.embeddings import OllamaEmbeddings
from langchain_community.vectorstores import Chroma
from soc_engine.config.settings import settings

# Disable warnings for local SSL overrides
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MITRE_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
LOCAL_CACHE_PATH = os.path.join(os.path.dirname(__file__), "enterprise-attack.json")
VECTOR_DB_DIR = "./chromadb_store"


def download_mitre_data() -> dict:
    """Downloads MITRE ATT&CK STIX data or loads it from local cache."""
    if os.path.exists(LOCAL_CACHE_PATH):
        print(f"[*] Loading MITRE ATT&CK data from local cache: {LOCAL_CACHE_PATH}")
        try:
            with open(LOCAL_CACHE_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"[!] Failed to read cached file: {e}. Re-downloading...")

    print(f"[*] Downloading MITRE ATT&CK STIX data from: {MITRE_STIX_URL}")
    try:
        resp = requests.get(MITRE_STIX_URL, timeout=30, verify=False)
        resp.raise_for_status()
        data = resp.json()
        
        # Save cache
        try:
            with open(LOCAL_CACHE_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            print(f"[+] Cached MITRE ATT&CK data locally at: {LOCAL_CACHE_PATH}")
        except Exception as e:
            print(f"[!] Warning: Failed to write cache file: {e}")
            
        return data
    except Exception as e:
        print(f"[!] Error downloading MITRE data: {e}")
        return {}


def build_mitre_knowledge_base():
    """Compiles MITRE enterprise techniques and loads them into ChromaDB."""
    print("=" * 60)
    print("      BUILDING MITRE ATT&CK KNOWLEDGE BASE (RAG)      ")
    print("=" * 60)

    # 1. Fetch STIX objects
    mitre_data = download_mitre_data()
    if not mitre_data or "objects" not in mitre_data:
        print("[!] No data retrieved. Aborting build.")
        return False

    # 2. Filter out attack-patterns (TTPs)
    documents = []
    metadatas = []
    ids = []

    print("[*] Processing STIX objects...")
    for obj in mitre_data["objects"]:
        if obj.get("type") == "attack-pattern":
            # Identify the external MITRE ID (e.g. T1059.001)
            external_refs = obj.get("external_references", [])
            technique_id = None
            for ref in external_refs:
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id")
                    break

            description = obj.get("description")
            name = obj.get("name")
            obj_id = obj.get("id")

            if technique_id and description and name and obj_id:
                # Store the document (description) along with metadata
                documents.append(description)
                metadatas.append({
                    "technique_id": technique_id,
                    "name": name
                })
                ids.append(obj_id)

    if not documents:
        print("[!] No techniques found in STIX JSON. Aborting.")
        return False

    print(f"[*] Found {len(documents)} enterprise techniques to load.")

    # 3. Connect to ChromaDB and load documents
    try:
        # Check if Ollama is responsive
        print(f"[*] Initialising Ollama embeddings using model '{settings.OLLAMA_MODEL}'...")
        embeddings = OllamaEmbeddings(
            model="nomic-embed-text",
            base_url=settings.OLLAMA_HOST
        )
        
        # Test connection by embedding a dummy string
        embeddings.embed_query("connection test")
        print("[+] Ollama embedding connection verified.")
        
    except Exception as e:
        print(f"[!] Ollama is not running or model '{settings.OLLAMA_MODEL}' is missing.")
        print(f"    Error: {e}")
        print("[!] Please ensure Ollama is running and run: ollama pull " + settings.OLLAMA_MODEL)
        print("[!] Aborting vector store compilation.")
        return False

    try:
        # Initialise Chroma
        print(f"[*] Writing to vector DB directory: {VECTOR_DB_DIR}")
        vectorstore = Chroma(
            persist_directory=VECTOR_DB_DIR,
            embedding_function=embeddings,
            collection_name="mitre_attack"
        )
        
        # Add to vector store in chunks to avoid overwhelming memory/network
        chunk_size = 100
        total = len(documents)
        print(f"[*] Writing vectors to ChromaDB in chunks of {chunk_size}...")
        
        for idx in range(0, total, chunk_size):
            chunk_docs = documents[idx:idx+chunk_size]
            chunk_metas = metadatas[idx:idx+chunk_size]
            chunk_ids = ids[idx:idx+chunk_size]
            
            vectorstore.add_documents(
                documents=[
                    # Wrap strings into LangChain Document format if using add_documents
                    # or use add_texts directly
                ],
                # Using add_texts is easier for raw strings
            )
            # Let's use vectorstore.add_texts for simplicity
            
        # Re-initialize to do add_texts:
        # Let's clear previous object and do it cleanly with add_texts
        
    except Exception as e:
        print(f"[!] ChromaDB write error: {e}")
        return False


def compile_database():
    mitre_data = download_mitre_data()
    if not mitre_data or "objects" not in mitre_data:
        print("[!] No data retrieved. Aborting build.")
        return False

    # Extract technique objects
    texts = []
    metadatas = []
    ids = []

    for obj in mitre_data["objects"]:
        if obj.get("type") == "attack-pattern":
            external_refs = obj.get("external_references", [])
            technique_id = None
            for ref in external_refs:
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id")
                    break

            description = obj.get("description")
            name = obj.get("name")
            obj_id = obj.get("id")

            if technique_id and description and name and obj_id:
                # We can prepend the name and technique ID to help retrieval
                content = f"Technique ID: {technique_id}\nName: {name}\nDescription: {description}"
                texts.append(content)
                metadatas.append({
                    "technique_id": technique_id,
                    "name": name
                })
                ids.append(obj_id)

    if not texts:
        print("[!] No techniques found.")
        return False

    print(f"[*] Compiled {len(texts)} techniques. Initialising embeddings...")

    try:
        embeddings = OllamaEmbeddings(
            model="nomic-embed-text",
            base_url=settings.OLLAMA_HOST
        )
        # Test connection
        embeddings.embed_query("test query")
    except Exception as e:
        print(f"[!] Ollama connection failed: {e}")
        print(f"[!] Make sure Ollama is running and you have run 'ollama pull {settings.OLLAMA_MODEL}'")
        return False

    try:
        # Initialize chroma store
        print("[*] Loading data into ChromaDB...")
        vectorstore = Chroma(
            persist_directory=VECTOR_DB_DIR,
            embedding_function=embeddings,
            collection_name="mitre_attack"
        )
        
        # Batch upload
        batch_size = 100
        for i in range(0, len(texts), batch_size):
            batch_texts = texts[i:i+batch_size]
            batch_metas = metadatas[i:i+batch_size]
            batch_ids = ids[i:i+batch_size]
            vectorstore.add_texts(
                texts=batch_texts,
                metadatas=batch_metas,
                ids=batch_ids
            )
            print(f"    [+] Loaded chunk {i // batch_size + 1}/{(len(texts) - 1) // batch_size + 1}")

        print("[+] ChromaDB Vector database successfully built!")
        return True
    except Exception as e:
        print(f"[!] Database load error: {e}")
        return False


if __name__ == "__main__":
    compile_database()
