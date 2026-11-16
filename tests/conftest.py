"""
Shared test setup. The environment is fixed *before* cjp is imported, because
cjp.config reads it at import time (and load_dotenv never overrides a variable
that is already set):

- CJP_DATA_DIR and CJP_RESULTS_DIR point at throwaway directories, so no test
  writes to data/ or the tracked results/. The response cache moves to each
  test's own tmp_path, so no test sees another's cached responses.
- The API key is a dummy and the indexer URL is unreachable, so a test that
  forgets to mock the network fails instead of spending money or reading the
  live SIEM. VM_HOST is empty, so nothing runs over SSH.
"""

import json
import os
import shutil
import tempfile
from pathlib import Path
from types import SimpleNamespace

os.environ["CJP_DATA_DIR"] = tempfile.mkdtemp(prefix="cjp-test-data-")
os.environ["CJP_RESULTS_DIR"] = tempfile.mkdtemp(prefix="cjp-test-results-")
os.environ["ANTHROPIC_API_KEY"] = "sk-test-dummy"
os.environ["INDEXER_URL"] = "https://127.0.0.1:1"
os.environ["WAZUH_URL"] = "https://127.0.0.1:1"
os.environ["VM_HOST"] = ""

import pytest  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"
FIXTURE_SESSION = FIXTURES / "session_20990101_000000"
REPO_ROOT = Path(__file__).parent.parent
LEGACY = REPO_ROOT / "data" / "legacy" / "2026-09"


@pytest.fixture(autouse=True)
def response_cache(tmp_path, monkeypatch) -> Path:
    """A fresh, empty response cache per test (cjp.cache)."""
    import cjp.cache as cache
    monkeypatch.setattr(cache, "CACHE_DIR", tmp_path / "cache")
    return tmp_path / "cache"


@pytest.fixture
def session_dir(tmp_path) -> Path:
    """A writable copy of the synthetic fixture session."""
    dst = tmp_path / FIXTURE_SESSION.name
    shutil.copytree(FIXTURE_SESSION, dst)
    return dst


@pytest.fixture
def data_dir() -> Path:
    from cjp.config import DATA_DIR
    return DATA_DIR


def read_jsonl(path) -> list[dict]:
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]


class FakeMessages:
    """Stands in for anthropic.Anthropic().messages. Records every request and
    answers with `reply` (a dict serialised to JSON, or a raw string) as a
    real anthropic Message, so the cache stores and rehydrates what the SDK
    would return. stop_details is a dict, e.g. {"type": "refusal", ...}."""

    def __init__(self, reply=None, stop_reason="end_turn", stop_details=None):
        self.calls = []
        self.reply = reply if reply is not None else {   # a valid Format A answer
            "technique_label": "sql_injection", "candidate_labels": [], "disposition": "escalate",
            "confidence": "high", "recommended_action": "Block it.", "event_type": "SQL injection",
            "severity": "high", "reasoning": "r", "evidence": "POST, /rest/user/login",
            "cognitive_notes": "n"}
        self.stop_reason = stop_reason
        self.stop_details = stop_details

    def create(self, **kwargs):
        from anthropic.types import Message
        self.calls.append(kwargs)
        text = self.reply if isinstance(self.reply, str) else json.dumps(self.reply)
        return Message.model_validate({
            "id": f"msg_fake_{len(self.calls)}", "type": "message", "role": "assistant",
            "model": kwargs["model"],
            "stop_reason": self.stop_reason,
            "stop_sequence": None,
            "stop_details": self.stop_details,
            "content": [{"type": "text", "text": text}],
            "usage": {"input_tokens": 100, "output_tokens": 20}})


@pytest.fixture
def fake_claude(monkeypatch) -> FakeMessages:
    import cjp.triage.client as client
    messages = FakeMessages()
    monkeypatch.setattr(client, "get_client", lambda: SimpleNamespace(messages=messages))
    return messages
