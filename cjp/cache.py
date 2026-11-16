"""
Response cache for Claude calls (Plan P2.5, decision 004).

One file per response under data/cache/responses/<key[:2]>/<key>.json, keyed
by the sha256 of the exact request sent to messages.create plus the repeat
number. The request already holds everything the plan's key names: the prompt
and output format (system prompt, and from P2.6 the output schema), the model,
any sampling parameter, and the alert payload. Volatile IDs never reach it:
the Wazuh document `id` and `@timestamp` are not sent, and every CID is
redacted (cjp.triage.prompt). Keying on the whole request instead of a
hand-picked tuple means a parameter added later cannot be forgotten, which
would silently replay a response to a different request.

An entry stores the request next to the response, so it can be audited and a
key collision or a hand-edited file is caught on read. Entries are never
overwritten: a refresh (`cjp triage --no-cache`) moves the old one aside as
<key>.superseded-<UTC time>.json. Writes are atomic (temp file + rename), so a
crash never leaves half an entry.
"""

import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from cjp.config import RESPONSE_CACHE_DIR

# Bump when the key material changes shape; old entries then simply miss.
KEY_VERSION = 1

# Read at call time, so tests can point it at a temp directory.
CACHE_DIR: Path = RESPONSE_CACHE_DIR

# How a call uses the cache: "use" reads and fills it; "refresh" always calls
# and supersedes the entry (--no-cache); "only" never calls and raises
# CacheMiss instead (--cache-only: re-running from cache with no spend).
CACHE_MODES = ("use", "refresh", "only")


class CacheMiss(LookupError):
    """Cache-only mode found no entry for this key."""


def _canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def cache_key(request: dict, repeat: int) -> str:
    """sha256 of the request sent to the API and the repeat number. Repeat n
    of the same request is a separate sample, so it gets its own entry."""
    material = {"key_version": KEY_VERSION, "request": request, "repeat": repeat}
    return hashlib.sha256(_canonical(material).encode()).hexdigest()


def entry_path(key: str) -> Path:
    return CACHE_DIR / key[:2] / f"{key}.json"


def has(key: str) -> bool:
    return entry_path(key).exists()


def get(key: str, request: dict) -> dict | None:
    """The cached entry for key, or None. Raises ValueError if the entry's
    stored request differs from this one (a collision or an edited file)."""
    path = entry_path(key)
    if not path.exists():
        return None
    entry = json.loads(path.read_text())
    if _canonical(entry.get("request")) != _canonical(request):
        raise ValueError(f"cache entry {path} does not match the request it is keyed by")
    return entry


def put(key: str, request: dict, repeat: int, response: dict, **provenance) -> Path:
    """Store a response (Message.model_dump(mode="json")). An existing entry
    for key is moved aside, not overwritten."""
    path = entry_path(key)
    path.parent.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    if path.exists():
        path.rename(path.with_name(f"{key}.superseded-{now.strftime('%Y%m%dT%H%M%S%fZ')}.json"))
    entry = {"key_version": KEY_VERSION, "key": key, "created_at": now.isoformat(),
             "repeat": repeat, **provenance, "request": request, "response": response}
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{key}.", suffix=".tmp")
    with os.fdopen(fd, "w") as f:
        json.dump(entry, f, indent=1)
        f.write("\n")
    os.replace(tmp, path)
    return path
