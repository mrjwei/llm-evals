"""
Frozen corpora (Plan §2.1, P3.5): the sessions an experiment runs on, copied
once and checksummed, so every run of every experiment reads the same bytes.

    cjp corpus freeze C1 --sessions session_<a> session_<b> session_<c>
    data/corpus/C1/
        corpus.json                  sessions, per-file sha256, provenance
        sessions/session_<id>/       read-only copies

Why: until now a run named a session directory under data/sessions/, which
nothing stopped from changing (a re-collection, a hand edit, the legacy
`…_no_ingest` copy that silently dropped the bodies). A corpus is written
once, never overwritten, and verified before every experiment run; run.json
records the sha256 of corpus.json, and tag prereg-C1 carries the same hash
(Plan §2.5), so a reported number pins its input data.
"""

import hashlib
import json
import re
import shutil
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cjp.config import CORPUS_DIR, SESSIONS_DIR

CORPUS_SCHEMA_VERSION = 1
_CORPUS_ID = re.compile(r"C\d+(-[a-z0-9]+)*")        # C1, C1-inj
ARMS = ("S1-plain", "S2-body-in-url", "S3-body-field")


@dataclass(frozen=True)
class Corpus:
    id: str
    path: Path
    meta: dict

    @property
    def sessions(self) -> list[Path]:
        return [self.path / "sessions" / s["name"] for s in self.meta["sessions"]]

    @property
    def sha256(self) -> str:
        return _sha256_file(self.path / "corpus.json")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _checksums(session_dir: Path) -> dict[str, str]:
    return {str(p.relative_to(session_dir)): _sha256_file(p)
            for p in sorted(session_dir.rglob("*")) if p.is_file() and p.name != ".DS_Store"}


def _resolve_session(ref: str, sessions_dir: Path) -> Path:
    """A session by name (`session_<id>` or `<id>`) under data/sessions/, or a path."""
    path = Path(ref)
    if path.is_dir():
        return path.resolve()
    for name in (ref, f"session_{ref}"):
        if (sessions_dir / name).is_dir():
            return (sessions_dir / name).resolve()
    raise FileNotFoundError(f"no session {ref!r} (looked for a directory, and under {sessions_dir})")


def _session_summary(session_dir: Path) -> tuple[dict, list[str]]:
    """What corpus.json records about one session, and why it might not be fit."""
    warnings = []
    manifest_path = session_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.is_file() else {}
    if not manifest:
        warnings.append(f"{session_dir.name}: no manifest.json")
    populated = manifest.get("arms_populated")
    if populated is not None and set(populated) != set(ARMS):
        warnings.append(f"{session_dir.name}: only {len(populated)} of 3 arms populated "
                        f"({', '.join(populated) or 'none'}) (Plan P3 acceptance needs all three)")
    if not (session_dir / "ingest_log.jsonl").is_file():
        warnings.append(f"{session_dir.name}: no ingest_log.jsonl, so L1 conditions get no bodies "
                        "and requests cluster by method and URL only")
    for w in manifest.get("warnings") or []:
        warnings.append(f"{session_dir.name}: manifest warning: {w}")
    summary = {
        "name": session_dir.name,
        "source": str(session_dir),
        "manifest_version": manifest.get("manifest_version"),
        "seed": manifest.get("seed"),
        "vm_deployed_sha": manifest.get("vm_deployed_sha"),
        "arms_populated": populated,
        "alerts": {"S1-plain": manifest.get("alert_count"),
                   "S2-body-in-url": manifest.get("enriched_alert_count"),
                   "S3-body-field": manifest.get("body_field_alert_count")},
    }
    return summary, warnings


def freeze(corpus_id: str, sessions: list[str], note: str | None = None,
           corpus_dir: Path = CORPUS_DIR, sessions_dir: Path = SESSIONS_DIR) -> Corpus:
    """Copy the sessions into data/corpus/<id>/, make the copies read-only and
    write corpus.json. Refuses an existing corpus: a corpus is never changed,
    only replaced by a new ID."""
    from cjp.runs import git_describe, git_sha
    if not _CORPUS_ID.fullmatch(corpus_id):
        raise ValueError(f"corpus ID {corpus_id!r} must look like C1 or C1-inj")
    if not sessions:
        raise ValueError("a corpus needs at least one session")
    dest = Path(corpus_dir) / corpus_id
    if dest.exists():
        raise FileExistsError(f"{dest} exists; a corpus is never overwritten (freeze a new ID, "
                              "e.g. C2, and say why in a decision record)")
    sources = [_resolve_session(ref, Path(sessions_dir)) for ref in sessions]
    names = [s.name for s in sources]
    if len(set(names)) != len(names):
        raise ValueError(f"duplicate sessions: {names}")

    entries, warnings = [], []
    tmp = dest.with_name(f".{corpus_id}.partial")
    if tmp.exists():
        raise FileExistsError(f"{tmp} is left from an interrupted freeze; look at it, remove it, "
                              "then freeze again")
    try:
        for src in sources:
            copy = tmp / "sessions" / src.name
            shutil.copytree(src, copy, ignore=shutil.ignore_patterns(".DS_Store"))
            summary, warn = _session_summary(copy)
            summary["files"] = _checksums(copy)
            entries.append(summary)
            warnings += warn
        meta = {
            "schema_version": CORPUS_SCHEMA_VERSION,
            "id": corpus_id,
            "created_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
            "note": " ".join(note.split()) if note else None,
            "git_sha": git_sha(),
            "git_describe": git_describe(),
            "sessions": entries,
            "warnings": warnings,
        }
        (tmp / "corpus.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n")
        for p in tmp.rglob("*"):
            if p.is_file():
                p.chmod(p.stat().st_mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
        tmp.rename(dest)      # appears complete or not at all
    except BaseException:
        if tmp.exists():
            for p in tmp.rglob("*"):
                if p.is_file():
                    p.chmod(p.stat().st_mode | stat.S_IWUSR)
            shutil.rmtree(tmp)
        raise
    return Corpus(corpus_id, dest, meta)


def load(corpus_id: str, corpus_dir: Path = CORPUS_DIR) -> Corpus:
    path = Path(corpus_dir) / corpus_id
    meta_file = path / "corpus.json"
    if not meta_file.is_file():
        raise FileNotFoundError(f"no corpus {corpus_id} ({meta_file} missing); "
                                f"freeze it first: cjp corpus freeze {corpus_id} --sessions …")
    return Corpus(corpus_id, path, json.loads(meta_file.read_text()))


def verify(corpus: Corpus) -> list[str]:
    """Every file still has the checksum corpus.json recorded, and no file
    was added. Returns the problems (empty: the corpus is intact)."""
    problems = []
    for entry in corpus.meta["sessions"]:
        session = corpus.path / "sessions" / entry["name"]
        if not session.is_dir():
            problems.append(f"{entry['name']}: missing")
            continue
        actual = _checksums(session)
        for rel, digest in entry["files"].items():
            if rel not in actual:
                problems.append(f"{entry['name']}/{rel}: missing")
            elif actual[rel] != digest:
                problems.append(f"{entry['name']}/{rel}: changed (sha256 differs)")
        for rel in sorted(set(actual) - set(entry["files"])):
            problems.append(f"{entry['name']}/{rel}: added after the freeze")
    return problems


def list_corpora(corpus_dir: Path = CORPUS_DIR) -> list[Corpus]:
    return [load(p.parent.name, corpus_dir) for p in sorted(Path(corpus_dir).glob("*/corpus.json"))]
