"""
Every setting the pipeline reads from the environment, in one place.

Before Plan P2.1 each legacy script read its own `os.getenv` calls at import
time, and only some of them called load_dotenv() first — wp2_collector.py
saw VM_HOST only because it happened to import wazuh_client.py (which loads
.env) before reading it. Now .env is loaded once, from the repo root rather
than the caller's working directory, and every other module imports from here.

Defaults are the legacy ones, unchanged; every variable is documented in
.env.example. Tracked settings that are part of the method, not the machine
(models and their request parameters, prices, scoring parameters), are in
config/settings.yaml, read through settings(). validate() checks both before
every command (Plan P2.10), so a typo stops the run at start-up with every
problem listed, instead of as a KeyError halfway through a paid batch.
"""

import functools
import os
from pathlib import Path
from urllib.parse import urlparse

import yaml
from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(REPO_ROOT / ".env")

# ── Local data (Plan §2.2: everything under data/, gitignored) ──────────────
# The legacy scripts wrote to ./sessions and ./outputs relative to the working
# directory. The run registry (data/runs/, Plan P2.4) replaces data/outputs/.
DATA_DIR = Path(os.getenv("CJP_DATA_DIR", REPO_ROOT / "data"))
SESSIONS_DIR = DATA_DIR / "sessions"
OUTPUTS_DIR = DATA_DIR / "outputs"          # legacy commands only (triage, map, metrics)
CORPUS_DIR = DATA_DIR / "corpus"
RUNS_DIR = DATA_DIR / "runs"                # <experiment>/<run>/run.json + generated INDEX.md
TRIAGE_JOBS_DIR = DATA_DIR / "triage_jobs"  # the web app's triage jobs (P6.2), never research runs
RATINGS_DIR = DATA_DIR / "ratings"          # <batch>/: blind rating items and each rater's scores (P6.6)

# ── Tracked research inputs and outputs (Plan §2.2, §2.3) ──────────────────
EXPERIMENTS_DIR = REPO_ROOT / "experiments"         # <ID>.yaml: the only place conditions exist
RESULTS_DIR = Path(os.getenv("CJP_RESULTS_DIR", REPO_ROOT / "results"))
CANONICAL_FILE = RESULTS_DIR / "canonical.yaml"     # which run each report figure comes from

TAXONOMY_DIR = REPO_ROOT / "taxonomy"               # labels.yaml: the technique labels (P2.6)
LEGACY_SYNONYM_TABLE = TAXONOMY_DIR / "legacy_synonyms.json"
BASELINES_FILE = TAXONOMY_DIR / "baselines.yaml"    # X0's lookup baselines (P4, decision 011)
RUBRIC_DIR = REPO_ROOT / "rubric"                   # expected_decisions.yaml, rating_rubric.yaml (P4)
EXPECTED_DECISIONS_FILE = RUBRIC_DIR / "expected_decisions.yaml"
RATING_RUBRIC_FILE = RUBRIC_DIR / "rating_rubric.yaml"
PROMPTS_DIR = REPO_ROOT / "prompts"                 # triage prompt and output formats (P2.6)
SETTINGS_FILE = REPO_ROOT / "config" / "settings.yaml"   # prices, scoring parameters (P2.7)


@functools.cache
def settings(path: Path = SETTINGS_FILE) -> dict:
    """config/settings.yaml, parsed once."""
    return yaml.safe_load(path.read_text())

# ── Claude ─────────────────────────────────────────────────────────────────
# Models and their request parameters are in config/settings.yaml (`models`,
# `triage`), so they are tracked with the method. The legacy runs used
# claude-sonnet-5; claude-sonnet-5-5 from 30 Sep (decision 003).
# CJP_TRIAGE_MODEL overrides the default for one shell: an alias or model ID
# from settings.yaml, never a free-form ID (its parameters would be unknown).
TRIAGE_MODEL_OVERRIDE = os.getenv("CJP_TRIAGE_MODEL") or None
# One file per Claude response, keyed by request + repeat (cjp/cache.py, Plan P2.5).
RESPONSE_CACHE_DIR = DATA_DIR / "cache" / "responses"


def model_profile(name: str | None = None) -> dict:
    """{alias, id, thinking, effort} for a model alias (`sonnet`) or one of
    the IDs in settings.yaml. None means the triage default: CJP_TRIAGE_MODEL
    if set, else settings.yaml `triage.model`. Raises ValueError for a model
    with no entry, whose accepted parameters would be a guess."""
    models = settings()["models"]
    name = name or TRIAGE_MODEL_OVERRIDE or settings()["triage"]["model"]
    for alias, spec in models.items():
        if name in (alias, spec["id"]):
            return {"alias": alias, "id": spec["id"], "thinking": spec.get("thinking"),
                    "effort": spec.get("effort")}
    raise ValueError(f"model {name!r} is not in config/settings.yaml `models` "
                     f"(known: {', '.join(models)})")

# ── Wazuh, through the SSH tunnel ───────────────────────────────────────────
# manager API (port 55000) — used for authentication only
WAZUH_URL = os.getenv("WAZUH_URL", "https://127.0.0.1:55000")
WAZUH_USER = os.getenv("WAZUH_USER", "wazuh")
WAZUH_PASS = os.getenv("WAZUH_PASS", "wazuh")

# indexer (port 9200) — used for alert retrieval
INDEXER_URL = os.getenv("INDEXER_URL", "https://127.0.0.1:9200")
INDEXER_USER = os.getenv("INDEXER_USER", "admin")
INDEXER_PASS = os.getenv("INDEXER_PASS", "SecretPassword")

# ── The VM ──────────────────────────────────────────────────────────────────
# SSH access is optional in online collection (manifest fields just stay
# null) and required for offline collection and `cjp vm deploy`.
VM_HOST = os.getenv("VM_HOST")
VM_USER = os.getenv("VM_USER", "jesse")

# Where `cjp vm deploy` puts the repo's vm/ on the VM (Plan P2.2; before
# that the VM ran from the checkout ~/juice-shop-wazuh). Absolute, because
# the agent's <localfile> paths and the indexer's `location` field are.
VM_ROOT = os.getenv("VM_ROOT", f"/home/{VM_USER}/cjp-vm")
VM_DATA_DIR = os.getenv("VM_DATA_DIR", f"{VM_ROOT}/juice-shop/data")
VM_SESSIONS_DIR = os.getenv("VM_SESSIONS_DIR", f"{VM_DATA_DIR}/sessions")
VM_ATTACKS_SH_PATH = os.getenv("VM_ATTACKS_SH_PATH", f"{VM_ROOT}/juice-shop/attacks.sh")
WAZUH_VERSION = os.getenv("WAZUH_VERSION", "4.14.4")
JUICE_SHOP_IMAGE = os.getenv("JUICE_SHOP_IMAGE", "bkimminich/juice-shop (unpinned)")

# One indexer `location` wildcard per SIEM evidence arm. They are disjoint:
# "access.log*" does not match "enriched_access.log.*" (different literal
# prefix), so each arm needs its own, and a missing one silently drops that
# arm's alerts (ARCHITECTURE §3).
JUICE_LOG_PATH = os.getenv(                     # S1-plain
    "JUICE_LOG_PATH", f"{VM_DATA_DIR}/logs/access.log*")
ENRICHED_JUICE_LOG_PATH = os.getenv(            # S2-body-in-url
    "ENRICHED_JUICE_LOG_PATH", f"{VM_DATA_DIR}/logs/enriched_access.log*")
BODY_FIELD_JUICE_LOG_PATH = os.getenv(          # S3-body-field
    "BODY_FIELD_JUICE_LOG_PATH", f"{VM_DATA_DIR}/logs/body_field_access.log*")
ARM_LOCATION_PATTERNS = {
    "S1-plain": JUICE_LOG_PATH,
    "S2-body-in-url": ENRICHED_JUICE_LOG_PATH,
    "S3-body-field": BODY_FIELD_JUICE_LOG_PATH,
}

# The Wazuh agent on the VM host that tails those logs.
WAZUH_AGENT_ID = os.getenv("WAZUH_AGENT_ID", "001")


# ── Validation at start-up (Plan P2.10) ─────────────────────────────────────
EFFORT_LEVELS = ("low", "medium", "high", "xhigh", "max")
# Read by an earlier version; setting it now does nothing, so say so.
RETIRED_ENV = {"CJP_TRIAGE_EFFORT": "set models.<alias>.effort in config/settings.yaml"}
REQUIRED_FILES = [TAXONOMY_DIR / "labels.yaml", LEGACY_SYNONYM_TABLE,
                  PROMPTS_DIR / "triage_v2.md", PROMPTS_DIR / "format_a.json",
                  PROMPTS_DIR / "format_b.json"]


class ConfigError(ValueError):
    """The configuration is unusable; the message lists every problem."""

    def __init__(self, problems: list[str]):
        self.problems = problems
        super().__init__("configuration problems:\n" + "\n".join(f"  - {p}" for p in problems))


def _number(value, low: float, high: float | None = None, integer: bool = False) -> bool:
    if isinstance(value, bool) or not isinstance(value, int if integer else (int, float)):
        return False
    return value >= low and (high is None or value <= high)


def _check_settings(doc) -> tuple[list[str], list[str]]:
    errors, warnings = [], []
    if not isinstance(doc, dict):
        return [f"{SETTINGS_FILE.name}: expected a mapping at the top level"], []
    for section in ("models", "triage", "api", "prices", "scoring"):
        if not isinstance(doc.get(section), dict):
            errors.append(f"{SETTINGS_FILE.name}: missing section '{section}'")
    if errors:
        return errors, warnings

    prices = doc["prices"]
    table = prices.get("usd_per_mtok")
    if not prices.get("source") or not prices.get("retrieved"):
        errors.append("prices: needs 'source' and 'retrieved' (where and when the prices were read)")
    if not isinstance(table, dict) or not table:
        errors.append("prices.usd_per_mtok: empty")
        table = {}
    for model, price in table.items():
        if not (isinstance(price, dict) and _number(price.get("input"), 0)
                and _number(price.get("output"), 0)):
            errors.append(f"prices.usd_per_mtok.{model}: needs numeric 'input' and 'output' ≥ 0")

    ids = set()
    for alias, spec in doc["models"].items():
        where = f"models.{alias}"
        if not isinstance(spec, dict) or not isinstance(spec.get("id"), str) or not spec["id"]:
            errors.append(f"{where}: needs an 'id' from the Anthropic models list")
            continue
        if spec["id"] in ids:
            errors.append(f"{where}: id {spec['id']} is listed twice")
        ids.add(spec["id"])
        unknown = set(spec) - {"id", "thinking", "effort"}
        if unknown:
            errors.append(f"{where}: unknown field(s) {sorted(unknown)}")
        thinking = spec.get("thinking")
        if thinking is not None and not (isinstance(thinking, dict) and thinking.get("type")):
            errors.append(f"{where}.thinking: must be a mapping with a 'type'")
        if spec.get("effort") is not None and spec["effort"] not in EFFORT_LEVELS:
            errors.append(f"{where}.effort: {spec['effort']!r} is not one of {', '.join(EFFORT_LEVELS)}")
        if spec["id"] not in table:
            warnings.append(f"{where}: {spec['id']} has no price in prices.usd_per_mtok; "
                            "its cost will be reported as unpriced")

    triage = doc["triage"]
    known = set(doc["models"]) | ids
    if triage.get("model") not in known:
        errors.append(f"triage.model: {triage.get('model')!r} is not an alias in 'models'")
    if not _number(triage.get("max_tokens"), 1, integer=True):
        errors.append("triage.max_tokens: must be a positive integer")
    if TRIAGE_MODEL_OVERRIDE is not None:
        if TRIAGE_MODEL_OVERRIDE not in known:
            errors.append(f"CJP_TRIAGE_MODEL={TRIAGE_MODEL_OVERRIDE}: not an alias or ID in "
                          f"config/settings.yaml 'models'")
        else:
            warnings.append(f"CJP_TRIAGE_MODEL={TRIAGE_MODEL_OVERRIDE} overrides triage.model "
                            f"({triage.get('model')}) in this shell")

    api = doc["api"]
    if not _number(api.get("max_retries"), 0, 20, integer=True):
        errors.append("api.max_retries: must be an integer from 0 to 20")
    if not _number(api.get("timeout_seconds"), 1):
        errors.append("api.timeout_seconds: must be a number ≥ 1")

    scoring = doc["scoring"]
    if not _number(scoring.get("bootstrap_resamples"), 100, integer=True):
        errors.append("scoring.bootstrap_resamples: must be an integer ≥ 100")
    if not _number(scoring.get("bootstrap_seed"), 0, integer=True):
        errors.append("scoring.bootstrap_seed: must be a non-negative integer")
    level = scoring.get("ci_level")
    if not (_number(level, 0) and 0 < level < 1):
        errors.append("scoring.ci_level: must be between 0 and 1, e.g. 0.95")
    return errors, warnings


def validate(settings_file: Path = SETTINGS_FILE) -> tuple[list[str], list[str]]:
    """(errors, warnings) for config/settings.yaml, the environment and the
    tracked input files. No network: `cjp doctor` checks reachability."""
    errors, warnings = [], []
    doc = None
    try:
        doc = yaml.safe_load(Path(settings_file).read_text())
    except FileNotFoundError:
        errors.append(f"{settings_file}: missing")
    except yaml.YAMLError as e:
        errors.append(f"{settings_file}: not valid YAML ({e})")
    if not errors:
        e, w = _check_settings(doc)
        errors += e
        warnings += w

    for name, url in (("WAZUH_URL", WAZUH_URL), ("INDEXER_URL", INDEXER_URL)):
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            errors.append(f"{name}={url!r}: must be a URL like https://127.0.0.1:9200")
    if not VM_ROOT.startswith("/"):
        errors.append(f"VM_ROOT={VM_ROOT!r}: must be an absolute path on the VM")
    for name, fix in RETIRED_ENV.items():
        if os.getenv(name):
            warnings.append(f"{name} is set but no longer read: {fix}")
    for path in REQUIRED_FILES:
        if not path.is_file():
            errors.append(f"{path.relative_to(REPO_ROOT)}: missing (tracked file; restore it from git)")
    return errors, warnings


def check() -> list[str]:
    """Raise ConfigError if validate() finds errors; return the warnings."""
    errors, warnings = validate()
    if errors:
        raise ConfigError(errors)
    return warnings
