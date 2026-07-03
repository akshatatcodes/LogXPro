import redis
import json
from datetime import datetime, timezone
from soc_engine.config.settings import settings
import soc_engine.models.db as db

# Initialize Redis client
redis_client = redis.Redis(
    host=settings.REDIS_HOST,
    port=settings.REDIS_PORT,
    db=settings.REDIS_DB,
    decode_responses=True
)

def get_redis_basket_key(host_name: str, user_name: str = None) -> str:
    user_part = user_name or "unknown"
    return f"active_basket:{host_name}:{user_part}"

def find_or_create_basket(host_name: str, user_name: str = None, source_ip: str = None) -> tuple:
    """
    Finds an existing open basket for the given host_name and user_name or creates a new one.
    Uses Redis as a fast cache and PostgreSQL as the source of truth.
    Returns: (basket, is_new)
    """
    # 1. Check Redis cache first
    redis_key = get_redis_basket_key(host_name, user_name)
    try:
        basket_id = redis_client.get(redis_key)
    except Exception:
        basket_id = None
    
    basket = None
    if basket_id:
        # Load from DB to ensure it's still open and get latest data
        try:
            basket = db.get_basket(basket_id)
            if basket and basket['status'] == 'open':
                # Slide the expiration window in Redis
                redis_client.expire(redis_key, settings.BASKET_EXPIRY_MINUTES * 60)
                return basket, False
        except Exception:
            pass
            
    # 2. Check DB if not cached in Redis (e.g. after a restart)
    try:
        ob = db.get_open_basket_for_host(host_name, user_name)
        if ob:
            # Found in DB, populate Redis cache and slide TTL
            basket_id = str(ob['basket_id'])
            try:
                redis_client.setex(redis_key, settings.BASKET_EXPIRY_MINUTES * 60, basket_id)
            except Exception:
                pass
            return ob, False
    except Exception:
        pass
            
    # 3. No active basket found, create a new one
    try:
        basket = db.create_basket(host_name, user_name, source_ip)
        basket_id = str(basket['basket_id'])
        try:
            redis_client.setex(redis_key, settings.BASKET_EXPIRY_MINUTES * 60, basket_id)
        except Exception:
            pass
        return basket, True
    except Exception:
        # Fallback dummy for simulator if database calls fail offline
        return {
            "basket_id": "simulated-basket-uuid-12345",
            "host_name": host_name,
            "user_name": user_name,
            "source_ip": source_ip,
            "status": "open",
            "confidence_score": 0,
            "matched_stages": []
        }, True

def add_event(basket_id: str, event_type: str, raw_event: dict, mitre_technique: str = None) -> dict:
    """
    Appends an event to the specified basket.
    """
    # Extract times safely
    event_time_str = raw_event.get("@timestamp") or raw_event.get("event", {}).get("created")
    event_time = None
    if event_time_str:
        try:
            event_time = datetime.fromisoformat(event_time_str.replace("Z", "+00:00"))
        except Exception:
            event_time = datetime.now(timezone.utc)
    else:
        event_time = datetime.now(timezone.utc)
        
    ingestion_time = datetime.now(timezone.utc)
    
    # Write event to DB
    try:
        evt = db.add_event_to_basket(
            basket_id=basket_id,
            event_type=event_type,
            raw_event=raw_event,
            mitre_technique=mitre_technique,
            event_time=event_time,
            ingestion_time=ingestion_time
        )
    except Exception:
        evt = {
            "event_id": "simulated-event-uuid",
            "basket_id": basket_id,
            "event_type": event_type,
            "raw_event": raw_event,
            "mitre_technique": mitre_technique,
            "event_time": event_time,
            "ingestion_time": ingestion_time
        }
    
    # Also cache events in Redis for fast matching if needed
    try:
        events_cache_key = f"basket_events:{basket_id}"
        redis_client.rpush(events_cache_key, json.dumps(raw_event))
        redis_client.expire(events_cache_key, settings.BASKET_EXPIRY_MINUTES * 60)
    except Exception:
        pass
    
    return evt
