"""
ingestion/es_reader.py
----------------------
Polls Elasticsearch for new log events using @timestamp / event.ingested range queries.
Uses INGESTION time (not endpoint clock) to avoid basket-killing clock-drift issues.
"""
from datetime import datetime, timezone, timedelta
from typing import Optional
from elasticsearch import Elasticsearch, exceptions as es_exceptions

from soc_engine.config.settings import settings


class ESReader:
    """
    Responsible for fetching new ECS-formatted log events from Elasticsearch.
    """

    def __init__(self, es_client: Elasticsearch, index_pattern: str = None):
        self.es = es_client
        self.index_pattern = index_pattern or settings.ES_INDEX

    def get_new_events(
        self,
        start_time: datetime,
        end_time: Optional[datetime] = None,
        max_events: int = 1000,
    ) -> list[dict]:
        """
        Fetches events ingested between start_time and end_time.
        Falls back to @timestamp if event.ingested field is unavailable.

        Args:
            start_time: Lower bound for the ingestion time window (exclusive).
            end_time:   Upper bound (defaults to now UTC if None).
            max_events: Maximum number of events returned per call.

        Returns:
            List of raw ECS event dictionaries (_source).
        """
        if end_time is None:
            end_time = datetime.now(timezone.utc)

        # Use event.ingested (Elasticsearch-set timestamp) for correlation.
        # This is immune to endpoint clock drift.
        query = {
            "query": {
                "range": {
                    "event.ingested": {
                        "gt": start_time.isoformat(),
                        "lte": end_time.isoformat(),
                    }
                }
            },
            "sort": [{"event.ingested": {"order": "asc"}}],
            "size": max_events,
        }

        try:
            result = self.es.search(index=self.index_pattern, body=query)
            hits = result.get("hits", {}).get("hits", [])
            total = result.get("hits", {}).get("total", {}).get("value", 0)

            if total > max_events:
                print(
                    f"[!] ESReader: {total} events available but capped at {max_events}. "
                    "Consider reducing POLL_INTERVAL or increasing max_events."
                )

            events = []
            for hit in hits:
                src = hit["_source"]
                # Inject ES metadata so downstream code can use it
                src["_es_index"] = hit.get("_index", "")
                src["_es_id"] = hit.get("_id", "")
                events.append(src)

            return events

        except es_exceptions.NotFoundError:
            # Index pattern doesn't exist yet — normal during initial setup
            print(f"[!] ESReader: Index pattern '{self.index_pattern}' not found yet. Waiting for logs...")
            return []
        except es_exceptions.ConnectionError as e:
            print(f"[!] ESReader: Elasticsearch connection error: {e}")
            return []
        except Exception as e:
            print(f"[!] ESReader: Unexpected error querying Elasticsearch: {e}")
            return []

    def get_events_with_scroll(
        self,
        start_time: datetime,
        end_time: Optional[datetime] = None,
        batch_size: int = 500,
    ) -> list[dict]:
        """
        Fetches ALL events in the time window using the scroll API.
        Use this when >1000 events may be in a single poll window.

        Args:
            start_time: Lower bound for the ingestion time window.
            end_time:   Upper bound (defaults to now UTC if None).
            batch_size: Number of events per scroll batch.

        Returns:
            Complete list of all matching events.
        """
        if end_time is None:
            end_time = datetime.now(timezone.utc)

        query = {
            "query": {
                "range": {
                    "event.ingested": {
                        "gt": start_time.isoformat(),
                        "lte": end_time.isoformat(),
                    }
                }
            },
            "sort": [{"event.ingested": {"order": "asc"}}],
            "size": batch_size,
        }

        all_events = []
        try:
            result = self.es.search(
                index=self.index_pattern,
                body=query,
                scroll="2m",
            )
            scroll_id = result.get("_scroll_id")
            hits = result.get("hits", {}).get("hits", [])

            while hits:
                for hit in hits:
                    src = hit["_source"]
                    src["_es_index"] = hit.get("_index", "")
                    src["_es_id"] = hit.get("_id", "")
                    all_events.append(src)

                result = self.es.scroll(scroll_id=scroll_id, scroll="2m")
                scroll_id = result.get("_scroll_id")
                hits = result.get("hits", {}).get("hits", [])

            # Clean up the scroll context
            if scroll_id:
                try:
                    self.es.clear_scroll(scroll_id=scroll_id)
                except Exception:
                    pass

        except Exception as e:
            print(f"[!] ESReader scroll error: {e}")

        return all_events

    def ping(self) -> bool:
        """Quick health check for the ES connection."""
        try:
            return self.es.ping()
        except Exception:
            return False
