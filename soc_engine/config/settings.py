import os


class Settings:
    # ------------------------------------------------------------------ #
    # Elasticsearch                                                          #
    # ------------------------------------------------------------------ #
    ES_HOST  = os.getenv("ES_HOST",  "http://127.0.0.1:9200")
    ES_INDEX = os.getenv("ES_INDEX", "logxpro-logs-*")

    # ------------------------------------------------------------------ #
    # Redis                                                                 #
    # ------------------------------------------------------------------ #
    REDIS_HOST = os.getenv("REDIS_HOST", "127.0.0.1")
    REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
    REDIS_DB   = int(os.getenv("REDIS_DB",   0))

    # ------------------------------------------------------------------ #
    # PostgreSQL                                                            #
    # ------------------------------------------------------------------ #
    DB_HOST     = os.getenv("DB_HOST",     "127.0.0.1")
    DB_PORT     = int(os.getenv("DB_PORT", 5433))
    DB_NAME     = os.getenv("DB_NAME",     "soc_engine")
    DB_USER     = os.getenv("DB_USER",     "soc_user")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "soc_pass")

    # ------------------------------------------------------------------ #
    # GRC / Rule configuration                                             #
    # ------------------------------------------------------------------ #
    GRC_PROFILE_DIR    = os.getenv("GRC_PROFILE_DIR",    "./soc_engine/config/grc_profiles")
    ACTIVE_GRC_PROFILE = os.getenv("ACTIVE_GRC_PROFILE", "default")

    # ------------------------------------------------------------------ #
    # Engine tuning                                                        #
    # ------------------------------------------------------------------ #
    POLL_INTERVAL         = int(os.getenv("POLL_INTERVAL",         10))    # seconds between ES polls
    BASKET_EXPIRY_MINUTES = int(os.getenv("BASKET_EXPIRY_MINUTES", 10))    # basket TTL in Redis
    DEDUP_WINDOW_SECONDS  = int(os.getenv("DEDUP_WINDOW_SECONDS",  300))   # alert dedup window (5 min)

    # ------------------------------------------------------------------ #
    # Phase 3: Enrichment API keys                                         #
    # ------------------------------------------------------------------ #
    VT_API_KEY        = os.getenv("VT_API_KEY",        "")   # VirusTotal free key
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "07144763ede2a6d4daf6e84e2bd6a5af9ccd9302a5013dcfcd764beaaf252bb055eff8cc52b94598")   # AbuseIPDB free key
    MISP_URL          = os.getenv("MISP_URL",          "http://localhost")
    MISP_API_KEY      = os.getenv("MISP_API_KEY",      "")

    # ------------------------------------------------------------------ #
    # Phase 4: Local LLM via Ollama                                        #
    # ------------------------------------------------------------------ #
    OLLAMA_HOST  = os.getenv("OLLAMA_HOST",  "http://localhost:11434")
    OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "tinyllama")

    # ------------------------------------------------------------------ #
    # Phase 5: TheHive SOAR integration                                    #
    # ------------------------------------------------------------------ #
    THEHIVE_URL     = os.getenv("THEHIVE_URL",     "http://localhost:9000")
    THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY", "")

    # ------------------------------------------------------------------ #
    # Phase 6: Playbooks, YARA, Webhooks                                   #
    # ------------------------------------------------------------------ #
    PLAYBOOK_DIR   = os.getenv("PLAYBOOK_DIR",   "./soc_engine/config/playbooks")
    YARA_RULES_DIR = os.getenv("YARA_RULES_DIR", "./soc_engine/config/rules/yara")
    WEBHOOK_URL    = os.getenv("WEBHOOK_URL",    "")   # Slack/Teams notify webhook (optional)


settings = Settings()
