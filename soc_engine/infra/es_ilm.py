"""
infra/es_ilm.py
----------------
Phase 6: Elasticsearch Index Lifecycle Management (ILM).

Reads the active GRC profile's `retention_days` setting and applies a
corresponding ILM policy to the logxpro-* index pattern.

This ensures log retention automatically matches client compliance requirements:
  - Finance (SOX): 365 days
  - Healthcare (HIPAA): 2190 days (6 years)
  - Default: 90 days

Called once during engine startup in live (non-simulate) mode.
"""
from soc_engine.config.settings import settings


_POLICY_NAME = "logxpro-ilm-policy"
_INDEX_TEMPLATE_NAME = "logxpro-template"


def apply_ilm_policy(es_client, grc_profile: dict) -> bool:
    """
    Applies an Elasticsearch ILM policy based on the active GRC profile's
    retention_days setting.

    Args:
        es_client: Active Elasticsearch client instance.
        grc_profile: The loaded GRC profile dict.

    Returns:
        True if the policy was successfully applied, False otherwise.
    """
    retention_days = grc_profile.get("retention_days", 90)
    client_name = grc_profile.get("client", "Default")

    print(f"[*] ILM: Applying retention policy for '{client_name}': {retention_days} days")

    # Build the ILM policy — warm phase at 7d, delete at retention_days
    policy = {
        "policy": {
            "phases": {
                "hot": {
                    "actions": {
                        "rollover": {
                            "max_size": "50gb",
                            "max_age": "7d"
                        }
                    }
                },
                "warm": {
                    "min_age": "7d",
                    "actions": {
                        "readonly": {},
                        "shrink": {"number_of_shards": 1},
                        "forcemerge": {"max_num_segments": 1}
                    }
                },
                "delete": {
                    "min_age": f"{retention_days}d",
                    "actions": {
                        "delete": {}
                    }
                }
            }
        }
    }

    try:
        # Apply the ILM policy
        es_client.ilm.put_lifecycle(name=_POLICY_NAME, policy=policy["policy"])
        print(f"[+] ILM: Policy '{_POLICY_NAME}' applied (retain={retention_days}d).")

        # Apply the index template so new logxpro-* indices automatically use the policy
        template = {
            "index_patterns": ["logxpro-*", "soc-alerts"],
            "settings": {
                "index": {
                    "lifecycle": {
                        "name": _POLICY_NAME,
                        "rollover_alias": "logxpro-logs"
                    },
                    "number_of_shards": 1,
                    "number_of_replicas": 0
                }
            }
        }
        es_client.indices.put_template(name=_INDEX_TEMPLATE_NAME, body=template)
        print(f"[+] ILM: Index template '{_INDEX_TEMPLATE_NAME}' applied to logxpro-* patterns.")
        return True

    except Exception as e:
        print(f"[!] ILM: Failed to apply policy: {e}")
        return False


def get_ilm_status(es_client) -> dict:
    """
    Retrieves the current ILM policy status for logxpro indices.

    Returns:
        Dict with policy summary or error message.
    """
    try:
        policy = es_client.ilm.get_lifecycle(name=_POLICY_NAME)
        return {"status": "active", "policy": policy}
    except Exception as e:
        return {"status": "missing", "error": str(e)}
