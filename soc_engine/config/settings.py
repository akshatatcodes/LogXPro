import os

class Settings:
    # Elasticsearch settings
    ES_HOST = os.getenv("ES_HOST", "http://127.0.0.1:9200")
    ES_INDEX = os.getenv("ES_INDEX", "logxpro-logs-*")

    # Redis settings
    REDIS_HOST = os.getenv("REDIS_HOST", "127.0.0.1")
    REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
    REDIS_DB = int(os.getenv("REDIS_DB", 0))

    # PostgreSQL settings
    DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
    DB_PORT = int(os.getenv("DB_PORT", 5433))
    DB_NAME = os.getenv("DB_NAME", "soc_engine")
    DB_USER = os.getenv("DB_USER", "soc_user")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "soc_pass")

    # GRC / Rule settings
    GRC_PROFILE_DIR = os.getenv("GRC_PROFILE_DIR", "./soc_engine/config/grc_profiles")
    ACTIVE_GRC_PROFILE = os.getenv("ACTIVE_GRC_PROFILE", "default")
    
    # Engine Poll Interval (seconds)
    POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", 10))
    BASKET_EXPIRY_MINUTES = int(os.getenv("BASKET_EXPIRY_MINUTES", 10))

    # API Keys for Enrichment
    VT_API_KEY = os.getenv("VT_API_KEY", "")
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

    # Ollama settings
    OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "phi3")

settings = Settings()
