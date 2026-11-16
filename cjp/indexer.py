"""
Wazuh indexer (OpenSearch) and manager API client, reached through the SSH
tunnel (wazuh-and-vm-notes §8). Moved from wazuh_client.py in Plan P2.1; the
connection settings and per-arm `location` wildcards now live in cjp.config.
"""

import warnings

import httpx
import urllib3

from cjp.config import (INDEXER_PASS, INDEXER_URL, INDEXER_USER, JUICE_LOG_PATH,
                        WAZUH_PASS, WAZUH_URL, WAZUH_USER)

urllib3.disable_warnings()


def _check_truncation(response_json: dict, returned: int, limit: int) -> None:
    total = response_json.get("hits", {}).get("total", {}).get("value")
    if total is not None and total > returned:
        warnings.warn(
            f"Truncated result: {total} alerts match the query but only "
            f"{returned} were returned (limit={limit}). Increase limit or "
            f"paginate with search_after to retrieve the rest.",
            stacklevel=3
        )


def get_token() -> str:
    """Authenticate with Wazuh manager API."""
    r = httpx.post(
        f"{WAZUH_URL}/security/user/authenticate",
        auth=(WAZUH_USER, WAZUH_PASS),
        verify=False
    )
    r.raise_for_status()
    return r.json()["data"]["token"]


def get_agent_config(agent_id: str, component: str, configuration: str) -> dict:
    """An agent's active configuration section, as the manager API reports
    it, e.g. ("001", "logcollector", "localfile") for its <localfile> blocks.
    Needs no sudo on the VM, unlike reading the agent's ossec.conf."""
    r = httpx.get(
        f"{WAZUH_URL}/agents/{agent_id}/config/{component}/{configuration}",
        headers={"Authorization": f"Bearer {get_token()}"},
        verify=False
    )
    r.raise_for_status()
    return r.json()["data"]


def get_alerts(limit: int = 50, location_pattern: str = JUICE_LOG_PATH) -> list[dict]:
    """Fetch most recent Juice Shop alerts from the indexer. location_pattern
    defaults to the plain access log; pass ENRICHED_JUICE_LOG_PATH to fetch
    alerts sourced from the payload-enriched log instead — the two wildcards
    don't overlap, so this never fetches both at once."""
    query = {
        "size": limit,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "must": [
                    {
                        "wildcard": {
                            "location": location_pattern
                        }
                    }
                ]
            }
        }
    }

    r = httpx.post(
        f"{INDEXER_URL}/wazuh-alerts-4.x-*/_search",
        json=query,
        auth=(INDEXER_USER, INDEXER_PASS),
        verify=False
    )
    r.raise_for_status()
    body = r.json()
    hits = body.get("hits", {}).get("hits", [])
    _check_truncation(body, len(hits), limit)
    return [hit["_source"] for hit in hits]


def get_alerts_since(
    after_timestamp: str, before_timestamp: str | None = None, limit: int = 100,
    location_pattern: str = JUICE_LOG_PATH, agent: str | None = None
) -> list[dict]:
    """Fetch Juice Shop alerts with timestamp in (after_timestamp, before_timestamp].

    before_timestamp is optional, but callers that care about session
    boundaries should always supply it: without an upper bound the query is
    open-ended, and alerts from a session started shortly after this one
    (which share the same location wildcard) will be pulled in too — see the
    session-boundary note in wazuh-and-vm-notes §9.

    location_pattern defaults to the plain access log (JUICE_LOG_PATH); pass
    ENRICHED_JUICE_LOG_PATH or BODY_FIELD_JUICE_LOG_PATH to fetch the same
    session's alerts for another arm — the wildcards are disjoint, so callers
    who want every arm call this once per arm.

    agent, if given, keeps only that agent's alerts, by ID ("001") or name
    (the web app's live triage window, Plan P6.2).
    """
    must = [
        {
            "wildcard": {
                "location": location_pattern
            }
        },
        {
            "range": {
                "timestamp": {
                    "gt": after_timestamp
                }
            }
        }
    ]
    if before_timestamp is not None:
        must.append({
            "range": {
                "timestamp": {
                    "lte": before_timestamp
                }
            }
        })

    if agent is not None:
        must.append({
            "bool": {
                "should": [{"term": {"agent.id": agent}}, {"term": {"agent.name": agent}}],
                "minimum_should_match": 1
            }
        })

    query = {
        "size": limit,
        "sort": [{"timestamp": {"order": "asc"}}],
        "query": {
            "bool": {
                "must": must
            }
        }
    }

    r = httpx.post(
        f"{INDEXER_URL}/wazuh-alerts-4.x-*/_search",
        json=query,
        auth=(INDEXER_USER, INDEXER_PASS),
        verify=False
    )
    r.raise_for_status()
    body = r.json()
    hits = body.get("hits", {}).get("hits", [])
    _check_truncation(body, len(hits), limit)
    return [hit["_source"] for hit in hits]
