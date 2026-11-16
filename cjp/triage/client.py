"""
The Claude call: one alert in, one parsed triage row out.

Moved from llm_analyser.py in Plan P2.1. Since 30 Sep it runs on anthropic
1.x and claude-sonnet-5-5 (the legacy runs used claude-sonnet-5). Which model
and which request parameters come from config/settings.yaml (`models`,
`triage`; Plan P2.10), because they differ by model: thinking stays off, as
in the legacy runs, which on Sonnet 5.5 is `between_tools` (`disabled`
returns a 400) and on Haiku 4.5 is no thinking field at all; Haiku takes no
effort either. No sampling parameter is sent: Sonnet 5.5 rejects non-default
values, so temperature 0 (Plan M7) is not available on this model. A safety decline
(stop_reason "refusal") is recorded as a failed row with its category, never
re-run on another model, so every row comes from the model it names.

Prompt v2 (Plan P2.6): the system prompt and the output schema depend on the
output format, A (full) or B (minimal). The schema goes to the API as
output_config.format, so the answer is generated to fit it, and is checked
again locally (cjp.triage.schema.validate). A row that fails the check is
kept with `schema_ok: false` and its errors.

The prompt and payload are built in cjp.triage.prompt. Every call goes
through the response cache (cjp.cache, Plan P2.5): a request already answered
for this repeat number is replayed from data/cache/responses/ and parsed by
the same code as a fresh one, so re-running triage costs nothing. The
Anthropic client is created on first use rather than at import, so importing
the package (tests, `cjp --help`) needs no API key. It retries connection
errors, 408, 409, 429 and 5xx with exponential backoff (the SDK's own, which
honours retry-after) up to settings.yaml `api.max_retries` times (Plan P2.10).
"""

import functools
import json
import os

import anthropic
from anthropic.types import Message

from cjp import cache
from cjp.config import model_profile, settings  # importing cjp.config loads .env
from cjp.runs import git_sha
from cjp.triage import schema
from cjp.triage.prompt import (DEFAULT_FORMAT, PROMPT_ID, build_alert_summary, prompt_version,
                               system_prompt, user_message)

# A request the API rejects as malformed, or a key or model it refuses, fails
# the same way for every alert: stop the batch at once instead of three times.
FATAL_ERRORS = (anthropic.AuthenticationError, anthropic.PermissionDeniedError,
                anthropic.NotFoundError, anthropic.BadRequestError)


def request_params(alert_summary: dict, fmt: str = DEFAULT_FORMAT,
                   model: str | None = None) -> dict:
    """Everything sent to messages.create for one alert. `model` is an alias
    or ID from settings.yaml `models` (default: the triage model). count_tokens
    takes the same dict (minus max_tokens), so estimates match real calls.
    For Sonnet 5.5 this is byte-for-byte the request sent before P2.10, so
    earlier cache entries still match."""
    profile = model_profile(model)
    output_config = {"format": {"type": "json_schema", "schema": schema.render_schema(fmt)}}
    if profile["effort"]:
        output_config["effort"] = profile["effort"]
    params = {
        "model": profile["id"],
        "max_tokens": settings()["triage"]["max_tokens"],
        "output_config": output_config,
        "system": system_prompt(fmt),
        "messages": [{"role": "user", "content": user_message(alert_summary)}],
    }
    if profile["thinking"]:
        params["thinking"] = profile["thinking"]
    return params


@functools.cache
def get_client() -> anthropic.Anthropic:
    api = settings()["api"]
    return anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"),
                               max_retries=api["max_retries"], timeout=api["timeout_seconds"])


def cache_key_for(alert: dict, ingest_entry: dict | None = None, repeat: int = 1,
                  fmt: str = DEFAULT_FORMAT, model: str | None = None) -> str:
    """The cache key analyse_alert() would use, without calling anything."""
    alert_summary, _ = build_alert_summary(alert, ingest_entry)
    return cache.cache_key(request_params(alert_summary, fmt, model), repeat)


def create_message(params: dict, repeat: int = 1, cache_mode: str = "use",
                   provenance: dict | None = None) -> tuple[Message, str, bool]:
    """messages.create through the response cache (cache.CACHE_MODES).
    provenance (e.g. prompt_version) is stored with a new cache entry.
    Returns (response, cache key, whether it came from the cache)."""
    if cache_mode not in cache.CACHE_MODES:
        raise ValueError(f"cache_mode must be one of {cache.CACHE_MODES}, not {cache_mode!r}")
    key = cache.cache_key(params, repeat)
    if cache_mode != "refresh":
        entry = cache.get(key, params)
        if entry is not None:
            return Message.model_validate(entry["response"]), key, True
        if cache_mode == "only":
            raise cache.CacheMiss(key)
    response = get_client().messages.create(**params)
    cache.put(key, params, repeat, response.model_dump(mode="json"),
              **(provenance or {}), git_sha=git_sha())
    return response, key, False


def extract_json(text: str) -> str:
    """Extract the first balanced {...} span from text (brace-matching)."""
    start = text.find("{")
    if start == -1:
        return text
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return text[start:]


def analyse_alert(alert: dict, ingest_entry: dict | None = None, *,
                  repeat: int = 1, cache_mode: str = "use", fmt: str = DEFAULT_FORMAT,
                  model: str | None = None) -> dict:
    """
    Send a single Wazuh alert to Claude and return structured analysis.
    Returns both the LLM output and token usage for WP4 evaluation.

    ingest_entry, if given, is this alert's matching row from a session's
    ingest_log.jsonl — see prompt.build_alert_summary().

    fmt is the output format, "A" (full) or "B" (minimal); see
    cjp.triage.schema. model is an alias or ID from settings.yaml `models`
    (default: the triage model).

    repeat numbers the sample (Plan M7: 3 repeats per condition); each repeat
    of the same request is cached separately. cache_mode: see cjp.cache.
    Responses that fail to parse, hit max_tokens or are refused are cached
    too: they are the model's answer, and re-asking until one parses would
    select results.
    """
    fmt = fmt.upper()
    alert_summary, ingest_matched = build_alert_summary(alert, ingest_entry)
    version = prompt_version(fmt)

    response, key, cache_hit = create_message(
        request_params(alert_summary, fmt, model), repeat, cache_mode,
        provenance={"prompt_version": version, "format": fmt})

    stop_reason = response.stop_reason
    text_blocks = [block.text for block in response.content if block.type == "text"]
    raw_output = "".join(text_blocks).strip()

    if stop_reason == "refusal":
        details = getattr(response, "stop_details", None)
        parsed = {"error": "refusal",
                  "category": getattr(details, "category", None),
                  "explanation": getattr(details, "explanation", None)}
        parse_ok = False
    elif stop_reason == "max_tokens":
        parsed = {"error": "truncated_at_max_tokens"}
        parse_ok = False
    else:
        try:
            parsed = json.loads(extract_json(raw_output))
            parse_ok = True
        except json.JSONDecodeError:
            parsed = {"error": "Failed to parse LLM output", "raw": raw_output}
            parse_ok = False
    schema_errors = schema.validate(parsed, fmt) if parse_ok else None

    return {
        "wazuh_alert_id": alert.get("id"),
        "wazuh_timestamp": alert.get("timestamp"),
        "wazuh_rule_id": alert.get("rule", {}).get("id"),
        "wazuh_rule_description": alert.get("rule", {}).get("description"),
        "ground_truth_location": alert.get("location"),
        "prompt_id": PROMPT_ID,
        "prompt_version": version,
        "format": fmt,
        "schema_version": schema.schema_version(fmt),
        "model": response.model,
        "git_sha": git_sha(),
        "ingest_matched": ingest_matched,
        "repeat": repeat,
        "cache_key": key,
        "cache_hit": cache_hit,
        "llm_output": parsed,
        "parse_ok": parse_ok,
        "schema_ok": schema_errors == [] if parse_ok else False,
        "schema_errors": schema_errors,
        "stop_reason": stop_reason,
        "token_usage": {
            "input_tokens": response.usage.input_tokens,
            "output_tokens": response.usage.output_tokens,
            "total_tokens": response.usage.input_tokens + response.usage.output_tokens
        }
    }
