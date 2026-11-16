"""
The run registry (Plan §2.3, P2.4): every research output has one address,
experiment → run → condition → repeat, and says for itself what produced it.

    experiments/X1.yaml                          question, RQ, corpus, conditions, reps
    data/runs/X1-evidence/2026-10-09T1030_ab12cd/
        run.json                                 provenance + status + headline
        conditions/<condition>/rep<N>/           verdicts.jsonl, scores.jsonl, …
    data/runs/INDEX.md                           generated after every change, never edited
    results/canonical.yaml                       tracked: which run each figure comes from

Why: before this, a run's setup lived partly in its filename tag
(`--variant`), partly in a `_meta.json` sidecar and partly in STATUS.md prose,
and nothing said which output a report figure came from. Now conditions exist
only in experiment YAMLs, run.json records the git SHA and `git describe`, the
config and prompt hashes and the corpus checksum, and a superseded run is
marked (status `superseded`, `superseded_by`), never overwritten. Deleting it
is a separate, confirmed `cjp runs prune`.

The legacy layout (data/outputs/<wp>/<session>/<tag>_v<N>/ plus sidecars,
moved here from output_paths.py in P2.1) stays at the bottom of this module
for `cjp triage | map | metrics` until `cjp experiment run` replaces them.
"""

import functools
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import yaml

from cjp import __version__
from cjp.config import CANONICAL_FILE, CORPUS_DIR, EXPERIMENTS_DIR, REPO_ROOT, RUNS_DIR

RUN_SCHEMA_VERSION = 1
STATUSES = ("running", "complete", "failed", "superseded")

_EXPERIMENT_ID = re.compile(r"[A-Z]\d+")                     # D1, X0, X1, H1
_SLUG = re.compile(r"[a-z0-9]+(-[a-z0-9]+)*")                # siem-coverage
_RQ = re.compile(r"RQ\d+")
# S1-plain__L1-alert+body__FA__sonnet, url-regex: a safe directory name.
_CONDITION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]*")
_PIN_KEY = re.compile(r"[A-Z][A-Za-z0-9_]*")                 # F3, F3_calibration, T1


# ── git provenance ───────────────────────────────────────────────────────────
def _git(*args: str) -> str | None:
    try:
        return subprocess.check_output(
            ["git", *args], cwd=REPO_ROOT, stderr=subprocess.DEVNULL).decode().strip()
    except (subprocess.CalledProcessError, OSError):
        return None


@functools.cache
def git_sha() -> str | None:
    """HEAD of this repo: which commit's code produced a row or report.
    Recorded next to prompt_version (which prompt wording) in every output.
    Before P2.1 three modules each ran `git rev-parse HEAD` in whatever the
    working directory was; this runs it in the repo root, once."""
    return _git("rev-parse", "HEAD")


def git_describe() -> str | None:
    """e.g. `prereg-C1-4-gab12cd-dirty` (Plan §2.5 rule 4): how far the code
    is from pre-registration, and whether it was uncommitted. Not cached,
    because the working tree can change during a long session."""
    return _git("describe", "--tags", "--always", "--dirty")


def _sha256_json(obj) -> str:
    """Hash of a JSON value, independent of key order and whitespace."""
    blob = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(blob.encode()).hexdigest()


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ── experiments ──────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Experiment:
    """One experiment YAML. `spec` is the whole file, so fields added in P4
    (prompt, format, baselines, …) reach the config hash without code here."""
    id: str
    slug: str
    question: str
    rq: tuple[str, ...]
    corpus: str
    conditions: tuple[str, ...]
    reps: int
    spec: dict
    path: Path | None = None

    @property
    def dir_name(self) -> str:
        return f"{self.id}-{self.slug}"

    @property
    def config_hash(self) -> str:
        return _sha256_json(self.spec)


def experiment_from_dict(spec: dict, path: Path | None = None) -> Experiment:
    """Validate an experiment spec. Errors name the file and the field."""
    where = str(path) if path else "experiment"

    def need(key, kind):
        if key not in spec:
            raise ValueError(f"{where}: missing '{key}'")
        if not isinstance(spec[key], kind):
            raise ValueError(f"{where}: '{key}' must be {kind.__name__}")
        return spec[key]

    eid, slug = need("id", str), need("slug", str)
    if not _EXPERIMENT_ID.fullmatch(eid):
        raise ValueError(f"{where}: id {eid!r} must look like X1 or D1")
    if not _SLUG.fullmatch(slug):
        raise ValueError(f"{where}: slug {slug!r} must be lower-case words joined by '-'")
    question = need("question", str).strip()
    rq = spec.get("rq")
    rq = (rq,) if isinstance(rq, str) else tuple(rq or ())
    if not rq or not all(isinstance(r, str) and _RQ.fullmatch(r) for r in rq):
        raise ValueError(f"{where}: rq must be RQ1, RQ2 or a list of them")
    corpus = need("corpus", str)
    conditions = tuple(need("conditions", list))
    if not conditions:
        raise ValueError(f"{where}: conditions is empty")
    for c in conditions:
        if not isinstance(c, str) or not _CONDITION.fullmatch(c):
            raise ValueError(f"{where}: condition {c!r} is not a safe directory name")
    dupes = [c for c, n in Counter(conditions).items() if n > 1]
    if dupes:
        raise ValueError(f"{where}: duplicate conditions {dupes}")
    reps = spec.get("reps", 1)
    if not isinstance(reps, int) or isinstance(reps, bool) or reps < 1:
        raise ValueError(f"{where}: reps must be a positive integer")
    return Experiment(eid, slug, question, rq, corpus, conditions, reps, spec, path)


def load_experiment(ref: str | Path, experiments_dir: Path = EXPERIMENTS_DIR) -> Experiment:
    """`X1` (→ experiments/X1.yaml) or a path to a YAML file."""
    path = Path(ref)
    if not path.suffix:
        path = Path(experiments_dir) / f"{ref}.yaml"
    if not path.is_file():
        raise FileNotFoundError(f"no experiment file {path}")
    path = path.resolve()
    spec = yaml.safe_load(path.read_text())
    if not isinstance(spec, dict):
        raise ValueError(f"{path}: expected a mapping at the top level")
    exp = experiment_from_dict(spec, path)
    if path.stem != exp.id:
        raise ValueError(f"{path}: file name must be {exp.id}.yaml")
    return exp


# ── runs ─────────────────────────────────────────────────────────────────────
class Run:
    """A run directory and its run.json. Every change is written through
    immediately, so a crash leaves an honest `running` or `failed` status."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.meta = json.loads((self.path / "run.json").read_text())

    @property
    def id(self) -> str:
        return self.meta["run_id"]

    @property
    def address(self) -> str:
        """`X1-evidence/2026-10-09T1030_ab12cd`: how canonical.yaml and the
        CLI name a run."""
        return f"{self.path.parent.name}/{self.id}"

    @property
    def status(self) -> str:
        return self.meta["status"]

    def _save(self) -> None:
        tmp = self.path / "run.json.tmp"
        tmp.write_text(json.dumps(self.meta, indent=2, ensure_ascii=False) + "\n")
        tmp.replace(self.path / "run.json")

    def condition_dir(self, condition: str, rep: int) -> Path:
        """conditions/<condition>/rep<N>/, created on first use. Only the
        experiment's own conditions and repeats have an address."""
        if condition not in self.meta["conditions"]:
            raise ValueError(f"{condition!r} is not a condition of {self.meta['experiment']} "
                             f"(conditions exist only in experiment YAMLs)")
        if not 1 <= rep <= self.meta["reps"]:
            raise ValueError(f"rep {rep} out of range 1..{self.meta['reps']}")
        d = self.path / "conditions" / condition / f"rep{rep}"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def update(self, **fields) -> None:
        """Record extra fields in run.json (written through at once)."""
        self.meta.update(fields)
        self._save()

    def reopen(self, config_hash: str) -> None:
        """Resume a `failed` run, or one left `running` by a killed process, at
        the same address (`cjp experiment run --resume`). Only with the same
        config_hash: the work already in the run must have had the same inputs.
        Each resume is recorded with the code version it ran from."""
        if self.status not in ("failed", "running"):
            raise ValueError(f"{self.address} is {self.status}; only a failed or interrupted "
                             "run can be resumed")
        if config_hash != self.meta["config_hash"]:
            raise ValueError(f"{self.address} was made with other inputs (config_hash differs: the "
                             "experiment YAML, models or cache mode changed); start a new run")
        self.meta.setdefault("resumes", []).append({
            "at": _now().isoformat(), "git_describe": git_describe(),
            "previous_status": self.status, "previous_error": self.meta.get("error")})
        self.meta.update(status="running", finished_at=None, error=None)
        self._save()
        write_index(self.path.parent.parent)

    def _end(self, status: str, **fields) -> None:
        if self.status != "running":
            raise ValueError(f"{self.address} is {self.status}, not running")
        self.meta.update(status=status, finished_at=_now().isoformat(), **fields)
        self._save()
        write_index(self.path.parent.parent)

    def finish(self, headline: str) -> None:
        """Mark complete with a one-line headline for INDEX.md."""
        headline = " ".join(str(headline).split())
        if not headline:
            raise ValueError("a complete run needs a headline")
        self._end("complete", headline=headline)

    def fail(self, error: str) -> None:
        self._end("failed", error=" ".join(str(error).split()))


def config_hash(experiment: Experiment, settings: dict | None = None) -> str:
    """What a run's inputs hash to: the experiment spec plus run-time settings.
    Two runs with the same hash had the same inputs (and a run can only be
    resumed with the hash it started with)."""
    return _sha256_json({"experiment": experiment.spec, "settings": settings or {}})


def _now() -> datetime:
    return datetime.now(timezone.utc).astimezone()


def new_run(experiment: Experiment, *, prompt_hash: str | None = None,
            model: str | dict | None = None, temperature: float | None = None,
            settings: dict | None = None, runs_dir: Path = RUNS_DIR,
            corpus_dir: Path = CORPUS_DIR) -> Run:
    """Create data/runs/<ID>-<slug>/<run id>/run.json with status `running`.

    `model` is one model ID, or {condition: model ID} when conditions differ
    (X3). `temperature` None means the API default (decision 003: Sonnet 5.5
    takes no sampling parameters). `settings` are run-time choices outside the
    YAML (e.g. cache off); they enter config_hash, so two runs with the same
    hash had the same inputs."""
    settings = settings or {}
    corpus_file = Path(corpus_dir) / experiment.corpus / "corpus.json"
    now = _now()
    exp_dir = Path(runs_dir) / experiment.dir_name
    exp_dir.mkdir(parents=True, exist_ok=True)
    while True:     # a new name every time; never reuse a directory
        run_id = f"{now:%Y-%m-%dT%H%M}_{secrets.token_hex(3)}"
        try:
            (exp_dir / run_id).mkdir()
            break
        except FileExistsError:
            continue
    meta = {
        "schema_version": RUN_SCHEMA_VERSION,
        "run_id": run_id,
        "experiment": experiment.id,
        "experiment_slug": experiment.slug,
        "question": experiment.question,
        "rq": list(experiment.rq),
        "experiment_file": (str(experiment.path.relative_to(REPO_ROOT))
                            if experiment.path and experiment.path.is_relative_to(REPO_ROOT)
                            else str(experiment.path) if experiment.path else None),
        "experiment_spec": experiment.spec,
        "conditions": list(experiment.conditions),
        "reps": experiment.reps,
        "corpus": {"id": experiment.corpus,
                   "sha256": _sha256_file(corpus_file) if corpus_file.is_file() else None},
        "config_hash": config_hash(experiment, settings),
        "settings": settings,
        "prompt_hash": prompt_hash,
        "model": model,
        "temperature": temperature,
        "git_sha": git_sha(),
        "git_describe": git_describe(),
        "cjp_version": __version__,
        "command": " ".join(sys.argv),
        "status": "running",
        "headline": None,
        "created_at": now.isoformat(),
        "finished_at": None,
    }
    (exp_dir / run_id / "run.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n")
    run = Run(exp_dir / run_id)
    if meta["corpus"]["sha256"] is None:
        print(f"[runs] warning: {corpus_file} not found; the run records no corpus checksum")
    if (meta["git_describe"] or "").endswith("-dirty"):
        print(f"[runs] warning: uncommitted code ({meta['git_describe']}); "
              "a canonical run needs a decision record for this (Plan P5)")
    write_index(runs_dir)
    return run


@contextmanager
def start_run(experiment: Experiment, **kwargs):
    """`with start_run(exp, …) as run: …; run.finish(headline)`. An exception,
    or leaving the block without finish(), marks the run failed."""
    with running(new_run(experiment, **kwargs)) as run:
        yield run


@contextmanager
def running(run: Run):
    """The body of start_run() for a run that already exists (a resumed one)."""
    try:
        yield run
    except BaseException as e:
        if run.status == "running":
            run.fail(f"{type(e).__name__}: {e}")
        raise
    if run.status == "running":
        run.fail("ended without a headline (finish() was not called)")


def list_runs(runs_dir: Path = RUNS_DIR) -> list[Run]:
    """Every run under data/runs/, ordered by experiment, then time."""
    return [Run(p.parent) for p in sorted(Path(runs_dir).glob("*/*/run.json"))]


def find_run(ref: str, runs_dir: Path = RUNS_DIR) -> Run:
    """A run by address (`X1-evidence/<id>`) or by bare run ID."""
    runs_dir = Path(runs_dir)
    if "/" in ref:
        path = runs_dir / ref.strip("/")
        if (path / "run.json").is_file():
            return Run(path)
        raise LookupError(f"no run {ref} under {runs_dir}")
    matches = [r for r in list_runs(runs_dir) if r.id == ref]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise LookupError(f"no run {ref} under {runs_dir}")
    raise LookupError(f"run ID {ref} is ambiguous: {', '.join(r.address for r in matches)}")


def supersede(old_ref: str, new_ref: str, runs_dir: Path = RUNS_DIR,
              canonical_file: Path = CANONICAL_FILE) -> Run:
    """Mark `old` superseded by `new` (same experiment). The old run's files
    stay until `prune`; a canonical pin on it shows in INDEX.md as a problem.
    `old` may be complete, failed, or left `running` by a killed process."""
    old, new = find_run(old_ref, runs_dir), find_run(new_ref, runs_dir)
    if old.path == new.path:
        raise ValueError("a run cannot supersede itself")
    if old.meta["experiment"] != new.meta["experiment"]:
        raise ValueError(f"{old.address} and {new.address} belong to different experiments")
    if old.status == "superseded":
        raise ValueError(f"{old.address} is already superseded by {old.meta.get('superseded_by')}")
    if old.status == "running" and new.meta["created_at"] <= old.meta["created_at"]:
        # A run left `running` by a killed process can only be replaced by a
        # later one; an earlier replacement would suggest it is still going.
        raise ValueError(f"{old.address} is running; only a later run can supersede it")
    if new.status != "complete":
        raise ValueError(f"{new.address} is {new.status}; the replacement must be complete")
    old.meta.update(status="superseded", superseded_by=new.address,
                    superseded_at=_now().isoformat())
    old._save()
    write_index(runs_dir, canonical_file)
    return old


# ── canonical pins (results/canonical.yaml, tracked) ────────────────────────
_CANONICAL_HEADER = """\
# Which run each report figure and table comes from (Plan §2.3 rule 4,
# decision 012). The paper cites only results/, never data/runs/.
#
# figures  what `cjp results build` makes: one entry per figure (F*) or table
#          (T*), its title and the experiments it reads (`from`). Edited by
#          hand and reviewed in git; removing an entry drops that output.
# pins     one canonical run per experiment, written by
#          `cjp runs mark-canonical <run>` (the key defaults to the run's
#          experiment). Re-pinning moves every figure that reads it.
#
# `cjp results build` regenerates results/figures/ and results/tables/ from
# these pins, reading the runs' stored outputs only (no API calls), and
# writes results/manifest.json with each output's runs and the checks.
"""


def load_canonical_doc(path: Path = CANONICAL_FILE) -> dict:
    """The whole of results/canonical.yaml: `figures` and `pins`."""
    path = Path(path)
    if not path.is_file():
        return {}
    doc = yaml.safe_load(path.read_text()) or {}
    for key in ("figures", "pins"):
        if not isinstance(doc.get(key) or {}, dict):
            raise ValueError(f"{path}: '{key}' must be a mapping")
    return doc


def load_canonical(path: Path = CANONICAL_FILE) -> dict[str, dict]:
    return load_canonical_doc(path).get("pins") or {}


def mark_canonical(ref: str, key: str | None = None, note: str | None = None,
                   runs_dir: Path = RUNS_DIR,
                   canonical_file: Path = CANONICAL_FILE) -> tuple[dict, dict | None]:
    """Pin a complete run as canonical under `key`, by default its
    experiment ID (decision 012). Returns (new pin, old pin)."""
    run = find_run(ref, runs_dir)
    key = key or run.meta["experiment"]
    if not _PIN_KEY.fullmatch(key):
        raise ValueError(f"pin key {key!r} must look like X1 or F3_calibration")
    if run.status != "complete":
        raise ValueError(f"{run.address} is {run.status}; only a complete run can be canonical")
    pins = load_canonical(canonical_file)
    old = pins.get(key)
    pin = {"run": run.address, "git_describe": run.meta.get("git_describe"),
           "pinned_at": _now().isoformat(timespec="seconds")}
    if note:
        pin["note"] = " ".join(note.split())
    pins[key] = pin
    _write_canonical(pins, canonical_file)
    write_index(runs_dir, canonical_file)
    return pin, old


def _write_canonical(pins: dict, path: Path) -> None:
    """Rewrite the pins, keeping the hand-edited `figures` section as it is."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    figures = load_canonical_doc(path).get("figures")
    body = ""
    if figures:
        body += yaml.safe_dump({"figures": figures}, sort_keys=False, allow_unicode=True,
                               default_flow_style=None, width=110) + "\n"
    body += yaml.safe_dump({"pins": dict(sorted(pins.items()))}, sort_keys=False,
                           allow_unicode=True, default_flow_style=False)
    path.write_text(_CANONICAL_HEADER + "\n" + body)


def _pins_by_run(pins: dict) -> dict[str, list[str]]:
    by_run: dict[str, list[str]] = {}
    for key, pin in pins.items():
        by_run.setdefault((pin or {}).get("run", ""), []).append(key)
    return by_run


# ── INDEX.md ─────────────────────────────────────────────────────────────────
def _cell(text) -> str:
    return str(text if text is not None else "").replace("|", "\\|").replace("\n", " ")


def render_index(runs: list[Run], pins: dict, generated_at: datetime | None = None) -> str:
    by_run = _pins_by_run(pins)
    stamp = (generated_at or _now()).isoformat(timespec="seconds")
    lines = [
        "# Runs index",
        "",
        f"Generated by `cjp` at {stamp} from every `<experiment>/<run>/run.json` below this "
        "folder, plus the pins in `results/canonical.yaml`. **Do not edit:** it is rewritten "
        "after every run (Plan §2.3).",
        "",
    ]
    if not runs:
        lines.append("No runs yet.")
    else:
        counts = Counter(r.status for r in runs)
        lines += [", ".join(f"{counts[s]} {s}" for s in STATUSES if counts[s]) + ".", "",
                  "| Run | Experiment | RQ | Status | Headline | Canonical | Code |",
                  "|---|---|---|---|---|---|---|"]
        for r in runs:
            m = r.meta
            target = "report.md" if (r.path / "report.md").is_file() else "run.json"
            status = r.status
            if status == "superseded":
                status = f"superseded by `{m.get('superseded_by', '?').split('/')[-1]}`"
            headline = m.get("error") if r.status == "failed" else m.get("headline")
            lines.append("| " + " | ".join([
                f"[{r.id}]({r.address}/{target})",
                _cell(f"{m['experiment']} {m.get('experiment_slug', '')}".strip()),
                _cell(", ".join(m.get("rq") or [])),
                _cell(status),
                _cell(headline),
                _cell(", ".join(sorted(by_run.get(r.address, [])))),
                _cell(f"`{m['git_describe']}`" if m.get("git_describe") else ""),
            ]) + " |")
    known = {r.address: r for r in runs}
    problems = []
    for key, pin in sorted(pins.items()):
        addr = (pin or {}).get("run")
        if addr not in known:
            problems.append(f"- `{key}` → `{addr}`: no such run")
        elif known[addr].status != "complete":
            problems.append(f"- `{key}` → `{addr}`: run is {known[addr].status}")
    if problems:
        lines += ["", "## Pin problems", "", *problems]
    return "\n".join(lines) + "\n"


def write_index(runs_dir: Path = RUNS_DIR, canonical_file: Path = CANONICAL_FILE) -> Path:
    """Regenerate data/runs/INDEX.md. Called after every run change."""
    runs_dir = Path(runs_dir)
    runs_dir.mkdir(parents=True, exist_ok=True)
    path = runs_dir / "INDEX.md"
    path.write_text(render_index(list_runs(runs_dir), load_canonical(canonical_file)))
    return path


# ── prune ────────────────────────────────────────────────────────────────────
def prune(runs_dir: Path = RUNS_DIR, canonical_file: Path = CANONICAL_FILE,
          yes: bool = False, confirm=input) -> int:
    """Delete superseded runs after showing the manifest (path · action ·
    reason) and asking once. Pinned runs are never deleted. Returns the
    number deleted."""
    pinned = _pins_by_run(load_canonical(canonical_file))
    superseded = [r for r in list_runs(runs_dir) if r.status == "superseded"]
    keep = [r for r in superseded if r.address in pinned]
    drop = [r for r in superseded if r.address not in pinned]
    for r in keep:
        print(f"[runs] keep {r.address}: superseded but pinned as "
              f"{', '.join(pinned[r.address])}; re-pin first")
    if not drop:
        print("[runs] nothing to prune")
        return 0
    print("[runs] prune manifest (path · action · reason):")
    for r in drop:
        print(f"  {r.path} · delete · superseded by {r.meta.get('superseded_by')} "
              f"on {str(r.meta.get('superseded_at', '?'))[:10]}")
    if not yes and confirm(f"Delete these {len(drop)} run(s)? [y/N] ").strip().lower() != "y":
        print("[runs] nothing deleted")
        return 0
    for r in drop:
        shutil.rmtree(r.path)
    write_index(runs_dir, canonical_file)
    print(f"[runs] deleted {len(drop)} run(s); INDEX.md regenerated")
    return len(drop)


# ── Legacy layout: data/outputs/<wp>/<session>/<tag>_v<N>/ ──────────────────
# Historically each script squeezed its run configuration into a filename tag,
# but several flags that change the result never reached it (--category,
# --synonym, --tolerance), so runs could overwrite each other's report. P2.1's
# fix, kept for the legacy commands: auto-versioned run directories plus a
# `<stem>_meta.json` sidecar recording the full invocation.

def resolve_run_dir(wp_output_dir: str, session_tag: str, run_tag_base: str) -> str:
    """Create and return outputs/<wp>/<session_tag>/<run_tag_base>_v<N>/,
    auto-incrementing N so a distinct run never collides with an existing one."""
    session_root = os.path.join(wp_output_dir, session_tag)
    os.makedirs(session_root, exist_ok=True)
    n = 1
    while os.path.isdir(os.path.join(session_root, f"{run_tag_base}_v{n}")):
        n += 1
    run_dir = os.path.join(session_root, f"{run_tag_base}_v{n}")
    os.makedirs(run_dir)
    return run_dir


def meta_path_for(artifact_path: str) -> str:
    """The <stem>_meta.json sidecar path for a given data/report file."""
    stem = os.path.splitext(artifact_path)[0]
    return f"{stem}_meta.json"


def write_meta(artifact_path: str, data: dict) -> str:
    """Write a single-invocation metadata sidecar next to artifact_path.
    Returns the sidecar's path."""
    path = meta_path_for(artifact_path)
    payload = {"created_at": datetime.now(timezone.utc).isoformat(), **data}
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)
        f.write("\n")
    return path


def append_invocation(artifact_path: str, entry: dict) -> str:
    """Append one invocation record to the <stem>_meta.json sidecar next to
    artifact_path, creating it if needed. Used by scripts that can be resumed
    or re-run against the same output file, so the history of CLI calls that
    contributed to it isn't lost."""
    path = meta_path_for(artifact_path)
    if os.path.exists(path):
        with open(path) as f:
            payload = json.load(f)
    else:
        payload = {"invocations": []}
    entry = {"timestamp": datetime.now(timezone.utc).isoformat(), **entry}
    payload["invocations"].append(entry)
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)
        f.write("\n")
    return path


def sanitize_tag(tag: str) -> str:
    """Make a user-supplied or derived tag filesystem-safe for use as a
    directory name component."""
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", tag).strip("-") or "run"
