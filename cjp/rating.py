"""
Expert rating (Plan P6.6, WP5′; METHODS §7): the blind rating queue behind
the web app's Rate page, the offline pack for a remote rater, and importing
what that pack saves.

    data/ratings/<batch>/
        batch.json             id, created_at, items, the calibration items, the rubric it was made with
        items.jsonl            one item per line: {"item", "alert", "body", "answer"}, which is
                               everything a rater sees and nothing else
        key.json               item → run, condition, session, alert, repeat, outcome. Written with
                               the batch (`cjp rating make-batch`, Plan P7.1) and never read here
        ratings/rater-A.json   one rater's scores, saved as they rate (rater-B.json likewise)

Blind by construction: the app and the pack read items.jsonl only, so no
condition, model, format name, ground truth or correctness can reach a rater
(rubric `blind: true`). The batch's maker must keep items.jsonl to what the
model saw and what it answered.

Order: the calibration items first, in batch order, as both raters go
through them together (METHODS §7). The rest follow in an order shuffled per
rater, seeded by batch and rater, so the app and the pack agree and a reload
keeps it.

Scores are R1–R4 on the rubric's 1–5 scales and R5 one of its choices. Each
change is saved at once (autosave), and a rating is complete when all five
are set. Nothing else is recorded: no comments, no timings (Plan P7.0).

The rubric's anchor wording may change once, in the calibration round. A
rater whose file has any scored item outside that round can't continue under
a changed rubric, so one rater's scores never mix two wordings.
"""

import hashlib
import json
import os
import random
import re
import threading
from datetime import datetime, timezone
from pathlib import Path

import yaml

from cjp import config

SCHEMA_VERSION = 1
RATERS = ("A", "B")
SCALE_ITEMS = ("R1", "R2", "R3", "R4")
CHOICE_ITEM = "R5"
ITEMS = (*SCALE_ITEMS, CHOICE_ITEM)
CHOICE_WORDS = {"escalate": "Escalate", "dismiss_false_positive": "Dismiss (false positive)",
                "needs_more_info": "Needs more info"}     # the Triage page's words
_BATCH_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")   # no dot: it is a UI path segment
_ITEM_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,31}")
PACK_DIR = Path(__file__).resolve().parent / "rating_pack"

_lock = threading.Lock()     # a rater file's read-modify-write


class RatingNotFound(LookupError):
    """No such batch, item, or rater file."""


class RatingConflict(RuntimeError):
    """The save or import would mix rubric wordings or replace saved scores."""


def ratings_root() -> Path:
    return config.RATINGS_DIR


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _write_json(path: Path, doc: dict) -> None:
    """Atomically: a reader never sees half a file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
    os.replace(tmp, path)


# ── rubric ───────────────────────────────────────────────────────────────────
def load_rubric(path: Path | None = None) -> dict:
    """rubric/rating_rubric.yaml as the app and the pack show it, with its
    version and sha256 (which ties each rater file to one wording)."""
    path = Path(path or config.RATING_RUBRIC_FILE)
    raw = path.read_bytes()
    doc = yaml.safe_load(raw)
    items = []
    for item_id in ITEMS:
        spec = doc["items"][item_id]
        entry = {"id": item_id, "name": spec["name"], "question": " ".join(str(spec["question"]).split())}
        if item_id == CHOICE_ITEM:
            entry["options"] = [{"value": v, "label": CHOICE_WORDS.get(v, v)} for v in spec["scale"]]
        else:
            low, high = spec["scale"]
            anchors = spec.get("anchors") or {}
            bad = [k for k, v in anchors.items() if isinstance(k, bool) or not isinstance(k, int)
                   or not low <= k <= high or not isinstance(v, str) or not v.strip()]
            if bad:    # e.g. an unquoted `no, …` that YAML read as false and split at a comma
                raise ValueError(f"{path}: {item_id} anchors {bad} are not 'point: words' on "
                                 f"{low}–{high}; quote anchor text that has a comma or yes/no")
            entry["scale"] = [low, high]
            entry["anchors"] = {str(k): v for k, v in anchors.items()}
        items.append(entry)
    return {"version": doc["version"], "sha256": hashlib.sha256(raw).hexdigest(),
            "blind": bool(doc.get("blind")), "items": items}


def check_scores(scores: dict, rubric: dict) -> dict:
    """Validated scores: a subset of R1–R5, each a value on its item's scale
    or None (cleared). Raises ValueError naming the first bad one."""
    specs = {i["id"]: i for i in rubric["items"]}
    out = {}
    for key, value in scores.items():
        if key not in specs:
            raise ValueError(f"{key!r} is not a rubric item (R1–R5)")
        spec = specs[key]
        if value is None:
            out[key] = None
        elif key == CHOICE_ITEM:
            allowed = [o["value"] for o in spec["options"]]
            if value not in allowed:
                raise ValueError(f"{key} must be one of {', '.join(allowed)}")
            out[key] = value
        else:
            low, high = spec["scale"]
            if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
                raise ValueError(f"{key} must be a whole number from {low} to {high}")
            out[key] = value
    return out


def complete(record: dict | None) -> bool:
    return bool(record) and all(record.get(k) is not None for k in ITEMS)


# ── batches ──────────────────────────────────────────────────────────────────
def batch_dir(batch_id: str, root: Path | None = None) -> Path:
    """The batch's directory. The ID must have the batch-ID shape, so a URL
    can never name a path outside data/ratings/."""
    if not _BATCH_ID.fullmatch(batch_id or ""):
        raise RatingNotFound(f"no rating batch {batch_id!r}")
    path = Path(root or ratings_root()) / batch_id
    if not (path / "batch.json").is_file():
        raise RatingNotFound(f"no rating batch {batch_id!r}")
    return path


def _check_rater(rater: str) -> str:
    if rater not in RATERS:
        raise RatingNotFound(f"rater must be {' or '.join(RATERS)}, not {rater!r}")
    return rater


class Batch:
    def __init__(self, batch_id: str, root: Path | None = None):
        self.path = batch_dir(batch_id, root)
        self.meta = json.loads((self.path / "batch.json").read_text())
        self.items = [json.loads(line) for line in (self.path / "items.jsonl").read_text().split("\n")
                      if line.strip()]
        self.by_id = {i["item"]: i for i in self.items}

    @property
    def id(self) -> str:
        return self.meta["id"]

    @property
    def calibration(self) -> list[str]:
        return [i for i in self.meta.get("calibration") or [] if i in self.by_id]

    def order(self, rater: str) -> list[str]:
        calibration = self.calibration
        rest = [i["item"] for i in self.items if i["item"] not in calibration]
        random.Random(f"{self.id}:{rater}").shuffle(rest)
        return calibration + rest

    def rater_path(self, rater: str) -> Path:
        return self.path / "ratings" / f"rater-{_check_rater(rater)}.json"

    def rater_doc(self, rater: str) -> dict | None:
        path = self.rater_path(rater)
        return json.loads(path.read_text()) if path.is_file() else None

    def item(self, item_id: str) -> dict:
        if item_id not in self.by_id:
            raise RatingNotFound(f"batch {self.id} has no item {item_id!r}")
        item = self.by_id[item_id]
        return {"item": item_id, "calibration": item_id in self.calibration,
                "alert": item["alert"], "body": item.get("body"), "answer": item["answer"]}


def create_batch(batch_id: str, items: list[dict], key: dict, calibration: list[str] | None = None,
                 root: Path | None = None, rubric_file: Path | None = None) -> Path:
    """Write a new batch (for `cjp rating make-batch`, Plan P7.1, and the
    tests). Each item is {"item", "alert", "body", "answer"} and nothing else,
    because the app shows items as they are. Never replaces a batch."""
    if not _BATCH_ID.fullmatch(batch_id or ""):
        raise ValueError(f"batch ID {batch_id!r}: letters, digits, '-' and '_' only, at most 64")
    path = Path(root or ratings_root()) / batch_id
    if path.exists():
        raise ValueError(f"{path} already exists; a batch is never replaced")
    seen = set()
    for item in items:
        extra = set(item) - {"item", "alert", "body", "answer"}
        if extra:
            raise ValueError(f"item {item.get('item')!r} has fields a rater must not see: {sorted(extra)}")
        if not _ITEM_ID.fullmatch(str(item.get("item") or "")) or item["item"] in seen:
            raise ValueError(f"item ID {item.get('item')!r} is missing, repeated or not opaque")
        if not isinstance(item.get("alert"), dict) or not isinstance(item.get("answer"), dict):
            raise ValueError(f"item {item['item']} needs an alert and an answer")
        seen.add(item["item"])
    unknown = [i for i in calibration or [] if i not in seen]
    if unknown:
        raise ValueError(f"calibration items not in the batch: {unknown}")
    rubric = load_rubric(rubric_file)
    path.mkdir(parents=True)
    with open(path / "items.jsonl", "w") as f:
        for item in items:
            f.write(json.dumps({"item": item["item"], "alert": item["alert"], "body": item.get("body"),
                                "answer": item["answer"]}) + "\n")     # ASCII: no U+2028 in a line
    _write_json(path / "key.json", key)
    _write_json(path / "batch.json", {
        "schema_version": SCHEMA_VERSION, "id": batch_id, "created_at": _now(), "items": len(items),
        "calibration": list(calibration or []),
        "rubric": {"version": rubric["version"], "sha256": rubric["sha256"]}})
    return path


def progress(batch: Batch, doc: dict | None) -> dict | None:
    """A rater's progress: items complete, and where to carry on."""
    if doc is None:
        return None
    ratings = doc.get("ratings") or {}
    order = doc.get("order") or batch.order(doc["rater"])
    done = [i for i in order if complete(ratings.get(i))]
    next_pos = next((n for n, i in enumerate(order) if not complete(ratings.get(i))), None)
    return {"complete": len(done), "total": len(order), "next": next_pos,
            "calibration_complete": sum(1 for i in batch.calibration if complete(ratings.get(i))),
            "started_at": doc.get("started_at"), "updated_at": doc.get("updated_at"),
            "via": doc.get("via")}


def list_batches(root: Path | None = None) -> list[dict]:
    """Every batch under data/ratings/ with each rater's progress."""
    root = Path(root or ratings_root())
    out = []
    for meta_path in sorted(root.glob("*/batch.json")):
        try:
            batch = Batch(meta_path.parent.name, root)
        except RatingNotFound:
            continue
        out.append({"id": batch.id, "created_at": batch.meta.get("created_at"), "items": len(batch.items),
                    "calibration": len(batch.calibration),
                    "raters": {r: progress(batch, batch.rater_doc(r)) for r in RATERS}})
    return out


# ── a rater's session ────────────────────────────────────────────────────────
def _session(batch: Batch, doc: dict) -> dict:
    return {"batch": batch.id, "rater": doc["rater"], "order": doc["order"],
            "calibration": batch.calibration, "ratings": doc.get("ratings") or {},
            "progress": progress(batch, doc), "rubric": doc["rubric"]}


def _rubric_guard(batch: Batch, doc: dict, rubric: dict) -> None:
    """Allow a changed rubric only while the rater has scored nothing
    outside the calibration round, then record the new one."""
    if doc["rubric"]["sha256"] == rubric["sha256"]:
        return
    outside = [i for i, r in (doc.get("ratings") or {}).items()
               if i not in batch.calibration and any(r.get(k) is not None for k in ITEMS)]
    if outside:
        raise RatingConflict(
            f"the rubric changed (version {doc['rubric']['version']} → {rubric['version']}) after rater "
            f"{doc['rater']} scored {len(outside)} item(s) outside the calibration round. Restore the "
            "rubric this rater started with, or start a new batch")
    doc["rubric"] = {"version": rubric["version"], "sha256": rubric["sha256"]}


def start(batch_id: str, rater: str, root: Path | None = None, rubric_file: Path | None = None) -> dict:
    """Begin, or carry on, rating as rater A or B."""
    batch = Batch(batch_id, root)
    rubric = load_rubric(rubric_file)
    with _lock:
        doc = batch.rater_doc(rater)
        if doc is None:
            doc = {"schema_version": SCHEMA_VERSION, "batch": batch.id, "rater": _check_rater(rater),
                   "rubric": {"version": rubric["version"], "sha256": rubric["sha256"]},
                   "order": batch.order(rater), "started_at": _now(), "updated_at": None,
                   "via": "app", "ratings": {}}
            _write_json(batch.rater_path(rater), doc)
    return _session(batch, doc)


def session(batch_id: str, rater: str, root: Path | None = None) -> dict:
    batch = Batch(batch_id, root)
    doc = batch.rater_doc(rater)
    if doc is None:
        raise RatingNotFound(f"rater {rater} has not started batch {batch_id}")
    return _session(batch, doc)


def item(batch_id: str, item_id: str, root: Path | None = None) -> dict:
    return Batch(batch_id, root).item(item_id)


def save(batch_id: str, rater: str, item_id: str, scores: dict, root: Path | None = None,
         rubric_file: Path | None = None) -> dict:
    """Merge one item's changed scores into the rater's file (autosave).
    Returns the item's record and the rater's progress."""
    batch = Batch(batch_id, root)
    batch.item(item_id)
    rubric = load_rubric(rubric_file)
    scores = check_scores(scores, rubric)
    with _lock:
        doc = batch.rater_doc(rater)
        if doc is None:
            raise RatingNotFound(f"rater {rater} has not started batch {batch_id}")
        _rubric_guard(batch, doc, rubric)
        record = {**(doc["ratings"].get(item_id) or {}), **scores, "saved_at": _now()}
        doc["ratings"][item_id] = record
        doc["updated_at"] = record["saved_at"]
        _write_json(batch.rater_path(rater), doc)
    return {"item": item_id, "record": record, "progress": progress(batch, doc)}


# ── offline pack and import ──────────────────────────────────────────────────
def _script_json(obj) -> str:
    """JSON safe inside <script type="application/json">: no '<', '>' or '&'
    can end the element or start a comment, and U+2028/9 stay escaped."""
    text = json.dumps(obj, ensure_ascii=False)
    for ch, esc in (("<", "\\u003c"), (">", "\\u003e"), ("&", "\\u0026"),
                    (" ", "\\u2028"), (" ", "\\u2029")):
        text = text.replace(ch, esc)
    return text


def _csp_hash(text: str) -> str:
    import base64
    return "'sha256-" + base64.b64encode(hashlib.sha256(text.encode()).digest()).decode() + "'"


def render_pack(batch_id: str, root: Path | None = None, rubric_file: Path | None = None) -> str:
    """One self-contained HTML file for a rater without the app. It needs no
    network and allows none (CSP `connect-src 'none'`); its script and style
    run only because their hashes are in the CSP. Scores autosave in the
    browser and leave as a downloaded JSON for `cjp rating import`."""
    batch = Batch(batch_id, root)
    rubric = load_rubric(rubric_file)
    data = {"schema_version": SCHEMA_VERSION, "batch": batch.id, "rubric": rubric,
            "calibration": batch.calibration, "orders": {r: batch.order(r) for r in RATERS},
            "items": {i["item"]: batch.item(i["item"]) for i in batch.items}}
    script = (PACK_DIR / "pack.js").read_text()
    style = (PACK_DIR / "pack.css").read_text()
    csp = (f"default-src 'none'; script-src {_csp_hash(script)}; style-src {_csp_hash(style)}; "
           "img-src 'none'; connect-src 'none'; form-action 'none'; base-uri 'none'")
    html = (PACK_DIR / "pack.html").read_text()
    for key, value in (("{{CSP}}", csp), ("{{BATCH}}", batch.id), ("{{STYLE}}", style),
                       ("{{DATA}}", _script_json(data)), ("{{SCRIPT}}", script)):
        html = html.replace(key, value)
    return html


def export_pack(batch_id: str, out: Path | None = None, root: Path | None = None) -> Path:
    """Write the pack, by default to data/ratings/<batch>/<batch>_rating-pack.html.
    An existing file with other content is never replaced."""
    batch = Batch(batch_id, root)
    out = Path(out or batch.path / f"{batch.id}_rating-pack.html")
    html = render_pack(batch_id, root)
    if out.exists() and out.read_text() != html:
        raise RatingConflict(f"{out} exists with other content; pass another --out")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html)
    return out


def import_ratings(path: Path, root: Path | None = None, rubric_file: Path | None = None) -> dict:
    """Check a pack's downloaded JSON and save it as the rater's file. It
    never replaces scores already saved for that rater. Returns a summary."""
    try:
        doc = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise ValueError(f"{path}: not a ratings file ({e})") from None
    if not isinstance(doc, dict) or doc.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"{path}: not a ratings file of schema version {SCHEMA_VERSION}")
    batch = Batch(str(doc.get("batch")), root)
    rater = _check_rater(doc.get("rater"))
    rubric = load_rubric(rubric_file)
    ratings = doc.get("ratings")
    if not isinstance(ratings, dict):
        raise ValueError(f"{path}: 'ratings' must map item IDs to scores")
    clean = {}
    for item_id, record in ratings.items():
        batch.item(item_id)
        if not isinstance(record, dict):
            raise ValueError(f"{path}: item {item_id}'s scores must be an object")
        scores = check_scores({k: v for k, v in record.items() if k in ITEMS}, rubric)
        clean[item_id] = {**scores, "saved_at": record.get("saved_at")}
    used = doc.get("rubric") if isinstance(doc.get("rubric"), dict) else {}
    new = {"schema_version": SCHEMA_VERSION, "batch": batch.id, "rater": rater,
           "rubric": {"version": used.get("version"), "sha256": used.get("sha256")},
           "order": batch.order(rater),
           "started_at": doc.get("started_at"), "updated_at": doc.get("updated_at"),
           "via": "pack", "imported_at": _now(), "ratings": clean}
    if not new["rubric"].get("sha256"):
        raise ValueError(f"{path}: no rubric version recorded")
    _rubric_guard(batch, new, rubric)
    dest = batch.rater_path(rater)
    with _lock:
        old = batch.rater_doc(rater)
        if old and any(any(r.get(k) is not None for k in ITEMS) for r in (old.get("ratings") or {}).values()):
            if old.get("ratings") == clean:
                return {"path": dest, "rater": rater, "batch": batch.id, "unchanged": True,
                        "progress": progress(batch, old)}
            raise RatingConflict(f"rater {rater} already has scores in {dest}; move that file away "
                                 "first if this import should replace it")
        _write_json(dest, new)
    return {"path": dest, "rater": rater, "batch": batch.id, "unchanged": False,
            "progress": progress(batch, new)}
