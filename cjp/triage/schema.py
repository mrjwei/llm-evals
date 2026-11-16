"""
The triage output schemas, Format A and Format B (Plan P2.6, M2–M3), and
their local validation.

prompts/format_a.json and format_b.json are JSON Schemas in the subset that
structured outputs accept (types, enum, required, additionalProperties false).
Their technique fields name an enum by an `x-cjp-enum` marker, which
render_schema() replaces with the values from taxonomy/labels.yaml, so the
label set is defined in one file only. The rendered schema is what the API
receives as output_config.format and what validate() checks locally. It
leaves out the field descriptions: the system prompt lists them already
(cjp.triage.prompt), and sending them twice cost about 300 input tokens per
call on Format A.

The API enforces the schema while generating, so validate() should only ever
fail on a refusal, a truncated answer or a cross-field rule that JSON Schema
cannot express: `candidate_labels` holds two or more labels when
technique_label is `uncertain`, and none otherwise. A failing answer is kept
and flagged, never re-asked (decision 004: re-asking until an answer passes
would select results).
"""

import copy
import functools
import hashlib
import json
from pathlib import Path

import yaml

from cjp.config import PROMPTS_DIR, TAXONOMY_DIR

LABELS_FILE = TAXONOMY_DIR / "labels.yaml"
FORMATS = {"A": PROMPTS_DIR / "format_a.json", "B": PROMPTS_DIR / "format_b.json"}
SPECIAL_LABELS = ("none", "other", "uncertain")


def short_hash(text: str) -> str:
    """The 8-hex-digit content hash used for every prompt and schema version."""
    return hashlib.sha256(text.encode()).hexdigest()[:8]


@functools.cache
def load_taxonomy(path: Path = LABELS_FILE) -> dict:
    taxonomy = yaml.safe_load(path.read_text())
    labels = taxonomy["labels"]
    if set(taxonomy["special"]) != set(SPECIAL_LABELS):
        raise ValueError(f"{path}: `special` must be exactly {SPECIAL_LABELS}")
    if clash := set(labels) & set(SPECIAL_LABELS):
        raise ValueError(f"{path}: {sorted(clash)} are reserved values, not labels")
    for group, members in taxonomy.get("coarse_groups", {}).items():
        for m in members:
            if labels.get(m, {}).get("coarse") != group:
                raise ValueError(f"{path}: {m} is listed in coarse group {group} but says otherwise")
    for gt, label in taxonomy.get("ground_truth", {}).items():
        if label not in labels:
            raise ValueError(f"{path}: ground truth {gt} maps to unknown label {label}")
    return taxonomy


def technique_labels() -> list[str]:
    """Every value technique_label may take: the labels, then none, other, uncertain."""
    return [*load_taxonomy()["labels"], *SPECIAL_LABELS]


def candidate_labels() -> list[str]:
    """Every value candidate_labels may list: the labels, or other."""
    return [*load_taxonomy()["labels"], "other"]


def _check_format(fmt: str) -> str:
    fmt = fmt.upper()
    if fmt not in FORMATS:
        raise ValueError(f"format must be one of {sorted(FORMATS)}, not {fmt!r}")
    return fmt


def _fill_enums(node):
    """Replace every x-cjp-enum marker with its enum; drop $comment and description."""
    if isinstance(node, dict):
        out = {k: _fill_enums(v) for k, v in node.items()
               if k not in ("x-cjp-enum", "$comment", "description")}
        marker = node.get("x-cjp-enum")
        if marker == "technique_label":
            out["enum"] = technique_labels()
        elif marker == "candidate_label":
            out["enum"] = candidate_labels()
        elif marker is not None:
            raise ValueError(f"unknown x-cjp-enum {marker!r}")
        return out
    if isinstance(node, list):
        return [_fill_enums(v) for v in node]
    return node


@functools.cache
def _format_file(fmt: str) -> str:
    return FORMATS[fmt].read_text()


@functools.cache
def _rendered(fmt: str) -> str:
    return json.dumps(_fill_enums(json.loads(_format_file(fmt))))


def render_schema(fmt: str) -> dict:
    """The JSON Schema of a format, as sent to the API."""
    return copy.deepcopy(json.loads(_rendered(_check_format(fmt))))


def schema_version(fmt: str) -> str:
    """Content hash of the rendered schema (so a taxonomy change changes it too)."""
    return short_hash(_rendered(_check_format(fmt)))


def fields(fmt: str) -> list[tuple[str, dict]]:
    """(name, rendered property schema + its description) in generation order."""
    described = json.loads(_format_file(_check_format(fmt)))["properties"]
    return [(name, {**spec, "description": described[name]["description"]})
            for name, spec in render_schema(fmt)["properties"].items()]


# ── Local validation ─────────────────────────────────────────────────────────

_TYPES = {"object": dict, "array": list, "string": str, "boolean": bool,
          "integer": int, "number": (int, float), "null": type(None)}


def _errors(value, schema: dict, path: str) -> list[str]:
    """The schema subset the format files use: type, enum, properties,
    required, additionalProperties false and items."""
    kind = schema.get("type")
    if kind and not isinstance(value, _TYPES[kind]):
        return [f"{path}: expected {kind}, got {type(value).__name__}"]
    errors = []
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: {value!r} is not an allowed value")
    if kind == "object":
        props = schema.get("properties", {})
        errors += [f"{path}.{k}: missing" for k in schema.get("required", []) if k not in value]
        if schema.get("additionalProperties") is False:
            errors += [f"{path}.{k}: not in the schema" for k in value if k not in props]
        for k, sub in props.items():
            if k in value:
                errors += _errors(value[k], sub, f"{path}.{k}")
    if kind == "array" and "items" in schema:
        for i, item in enumerate(value):
            errors += _errors(item, schema["items"], f"{path}[{i}]")
    return errors


def validate(output, fmt: str) -> list[str]:
    """Every way `output` breaks the format's schema or the candidate rule.
    An empty list means valid."""
    errors = _errors(output, render_schema(fmt), "$")
    if errors or "candidate_labels" not in output:
        return errors
    label, candidates = output["technique_label"], output["candidate_labels"]
    if label == "uncertain" and len(set(candidates)) < 2:
        errors.append("$.candidate_labels: uncertain needs two or more candidates")
    if label != "uncertain" and candidates:
        errors.append("$.candidate_labels: must be empty unless technique_label is uncertain")
    return errors
