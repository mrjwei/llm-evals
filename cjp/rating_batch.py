"""
`cjp rating make-batch` (Plan P7.1; METHODS §7): the X5 rating batch, drawn
from the pinned X1 and X2 runs and written with cjp.rating.create_batch().

    cjp rating make-batch --from X1,X2 --n 48 --seed 7

Cells (METHODS §7): the three S1 conditions the rubric compares.

    X1  S1-plain__L0-alert__FA__sonnet          evidence: alert only
    X1  S1-plain__L1-alert+body__FA__sonnet     evidence: alert + body, Format A
    X2  S1-plain__L1-alert+body__FB__sonnet     the same evidence, Format B

X2's FA half replays X1's cache, so its answers are X1's; X2 contributes FB.

Strata (decision 021): every cell gets the same number of items in each of
attack-correct, attack-wrong, attack-abstained (the fine outcome) and benign
(any outcome), so n must be a multiple of 12. Calibration adds 6 items on top
(2 per cell: one benign and one attack item, whose outcome rotates abstained,
wrong, correct across the cells). They are rated together and never analysed.

Each request appears once in the whole batch: the draw works on request
clusters (METHODS §6), so a rater never sees the same request twice, in
another session, repeat, evidence level or format. The scarcest stratum is
drawn first. Within a chosen cluster, one row (session × repeat) is picked at
random. Everything is seeded, so the same pins and seed give the same batch.

What a rater sees is rebuilt from the frozen corpus with the code that built
the prompt (cjp.triage.prompt.build_alert_summary) and checked against the
verdict's cache key: if the alert, the body or the condition differ from what
the model was sent, the key differs and the batch is refused. The answer is
the verdict's llm_output as stored.

This module reads ground truth (scores.jsonl) and writes it to key.json only.
cjp.rating, which serves the raters, never imports it. Its printout gives
counts per cell and stratum, never which item is which, because Jesse is
both the batch's maker and rater A.
"""

import json
import random
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from cjp import corpus as corpus_mod, rating, runs
from cjp.config import CANONICAL_FILE, CORPUS_DIR, RUNS_DIR
from cjp.experiment import parse_condition
from cjp.results import check_pin

CELLS = (("X1", "S1-plain__L0-alert__FA__sonnet"),
         ("X1", "S1-plain__L1-alert+body__FA__sonnet"),
         ("X2", "S1-plain__L1-alert+body__FB__sonnet"))
CELL_NAMES = ("S1xL0-FA", "S1xL1-FA", "S1xL1-FB")
STRATA = ("attack-correct", "attack-wrong", "attack-abstained", "benign")
# One benign and one attack calibration item per cell; the attack outcome
# rotates so the 6 cover all three (decision 021).
CALIBRATION = (("attack-abstained", "benign"), ("attack-wrong", "benign"), ("attack-correct", "benign"))
DEFAULT_BATCH = "X5"
BODY_FIELDS = ("request_body", "response_body")


@dataclass(frozen=True)
class Demand:
    cell: int
    stratum: str
    calibration: bool


def stratum(row: dict) -> str | None:
    """A scored row's stratum, or None when it is not scored (unattributed,
    aggregate) or has no answer to rate."""
    if row.get("is_attack") is None or row.get("fine") is None:
        return None
    if not row["is_attack"]:
        return "benign"
    return f"attack-{row['fine']}" if f"attack-{row['fine']}" in STRATA else None


def demands(n: int) -> list[Demand]:
    """Every slot to fill: n analysed (n/12 per cell × stratum), then 6 for calibration."""
    per = len(CELLS) * len(STRATA)
    if n <= 0 or n % per:
        raise ValueError(f"--n must be a positive multiple of {per} "
                         f"({len(CELLS)} cells × {len(STRATA)} strata); got {n}")
    out = [Demand(c, s, False) for c in range(len(CELLS)) for s in STRATA for _ in range(n // per)]
    out += [Demand(c, s, True) for c, strata in enumerate(CALIBRATION) for s in strata]
    return out


def allocate(pools: dict[tuple[int, str], dict[str, list[dict]]], wanted: list[Demand],
             rng: random.Random) -> list[tuple[Demand, dict]]:
    """Fill each demand with one row from a cluster no other demand used.
    pools: (cell, stratum) → cluster → rows. Greedy, scarcest first: the
    next slot filled is the one with the least room (clusters still free
    minus slots still open in that pool), so a small stratum is never
    starved by a large one that shares its requests."""
    open_slots = list(wanted)
    used: set[str] = set()
    out = []
    while open_slots:
        def room(d: Demand) -> int:
            free = sum(1 for c in pools.get((d.cell, d.stratum), {}) if c not in used)
            return free - sum(1 for o in open_slots if (o.cell, o.stratum) == (d.cell, d.stratum))
        slot = min(open_slots, key=lambda d: (room(d), d.calibration, d.cell, STRATA.index(d.stratum)))
        free = sorted(c for c in pools.get((slot.cell, slot.stratum), {}) if c not in used)
        if not free:
            have = len(pools.get((slot.cell, slot.stratum), {}))
            raise ValueError(f"{CELL_NAMES[slot.cell]} {slot.stratum}: no request left "
                             f"({have} distinct in the run, the rest already drawn); lower --n")
        cluster = rng.choice(free)
        rows = sorted(pools[(slot.cell, slot.stratum)][cluster],
                      key=lambda r: (r["session"], r["repeat"], r["wazuh_alert_id"]))
        out.append((slot, rng.choice(rows)))
        used.add(cluster)
        open_slots.remove(slot)
    return out


def pinned_runs(sources: list[str], canonical_file: Path, runs_dir: Path) -> dict[str, runs.Run]:
    """The pinned run of each experiment the cells read; refuses a missing,
    incomplete or (with a message) unclean pin."""
    needed = sorted({e for e, _ in CELLS})
    if sorted(set(sources)) != needed:
        raise ValueError(f"--from must be {','.join(needed)}: METHODS §7 fixes the cells to "
                         + "; ".join(f"{e} {c}" for e, c in CELLS))
    pins = runs.load_canonical(canonical_file)
    known = {r.address: r for r in runs.list_runs(runs_dir)}
    out = {}
    for exp_id in needed:
        run, problems = check_pin(exp_id, pins.get(exp_id), known)
        if run is None or problems:
            raise ValueError("; ".join(problems))
        out[exp_id] = run
    return out


def _corpus_for(run: runs.Run, corpus_dir: Path) -> corpus_mod.Corpus:
    meta = run.meta["corpus"]
    corp = corpus_mod.load(meta["id"], corpus_dir)
    if corp.sha256 != meta["sha256"]:
        raise ValueError(f"{run.address} read corpus {meta['id']} {meta['sha256'][:8]}, "
                         f"but {corp.path} is now {corp.sha256[:8]}")
    problems = corpus_mod.verify(corp)
    if problems:
        raise ValueError(f"corpus {corp.id} changed since its freeze: {problems[:3]}")
    return corp


def _verdict(run: runs.Run, condition: str, row: dict) -> dict:
    path = run.path / "conditions" / condition / f"rep{row['repeat']}" / row["session"] / "verdicts.jsonl"
    for line in path.read_text().splitlines():
        if line.strip():
            v = json.loads(line)
            if v.get("wazuh_alert_id") == row["wazuh_alert_id"]:
                return v
    raise ValueError(f"{path}: no verdict for alert {row['wazuh_alert_id']}")


class _Sessions:
    """Each corpus session's alerts (per alerts file) and ingest log, read once."""

    def __init__(self, corp: corpus_mod.Corpus):
        self.dirs = {p.name: p for p in corp.sessions}
        self._alerts, self._ingest = {}, {}

    def alert(self, session: str, alerts_file: str, alert_id: str) -> dict:
        from cjp.triage.batch import load_alerts_from_session
        key = (session, alerts_file)
        if key not in self._alerts:
            self._alerts[key] = {a.get("id"): a for a in load_alerts_from_session(str(self.dirs[session]),
                                                                                   alerts_file)}
        if alert_id not in self._alerts[key]:
            raise ValueError(f"{session}/{alerts_file}: no alert {alert_id}")
        return self._alerts[key][alert_id]

    def ingest(self, session: str) -> dict:
        from cjp.triage.batch import load_ingest_log
        if session not in self._ingest:
            self._ingest[session] = load_ingest_log(str(self.dirs[session]))
        return self._ingest[session]


def build_item(run: runs.Run, condition: str, row: dict, sessions: _Sessions) -> tuple[dict, dict]:
    """What the model was sent (alert and body) and what it answered, as an
    item without its ID, plus the verdict. Refused unless the rebuilt
    request has the verdict's cache key."""
    from cjp.triage.batch import make_jobs
    from cjp.triage.client import cache_key_for
    from cjp.triage.prompt import build_alert_summary
    cond = parse_condition(condition)
    verdict = _verdict(run, condition, row)
    if not (verdict.get("parse_ok") and verdict.get("schema_ok") and isinstance(verdict.get("llm_output"), dict)):
        raise ValueError(f"{run.address} {condition} alert {row['wazuh_alert_id']}: no valid answer to rate")
    alert = sessions.alert(row["session"], cond.alerts_file, row["wazuh_alert_id"])
    [(alert, entry)] = make_jobs([alert], sessions.ingest(row["session"]) if cond.with_body else None)
    key = cache_key_for(alert, entry, row["repeat"], cond.fmt, cond.model)
    if key != verdict.get("cache_key"):
        raise ValueError(f"{run.address} {condition} alert {row['wazuh_alert_id']} rep {row['repeat']}: "
                         "the rebuilt request is not the one the model answered (cache key differs)")
    summary, _ = build_alert_summary(alert, entry)
    body = {f: summary.pop(f) for f in BODY_FIELDS if f in summary}
    return {"alert": summary, "body": body or None, "answer": verdict["llm_output"]}, verdict


def _item_ids(count: int, rng: random.Random) -> list[str]:
    ids: list[str] = []
    while len(ids) < count:
        candidate = f"x{rng.getrandbits(32):08x}"
        if candidate not in ids:
            ids.append(candidate)
    return ids


def make_batch(sources: list[str], n: int, seed: int, batch_id: str = DEFAULT_BATCH,
               canonical_file: Path = CANONICAL_FILE, runs_dir: Path = RUNS_DIR,
               corpus_dir: Path = CORPUS_DIR, root: Path | None = None,
               dry_run: bool = False) -> dict:
    """Draw and (unless dry_run) write the batch. Returns counts only:
    per cell × stratum, calibration, and where it was written."""
    pinned = pinned_runs(sources, canonical_file, runs_dir)
    pools: dict[tuple[int, str], dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    for c, (exp_id, condition) in enumerate(CELLS):
        if condition not in pinned[exp_id].meta["conditions"]:
            raise ValueError(f"{pinned[exp_id].address} has no condition {condition}")
        for line in (pinned[exp_id].path / "conditions" / condition / "scores.jsonl").read_text().splitlines():
            if line.strip():
                row = json.loads(line)
                s = stratum(row)
                if s:
                    pools[(c, s)][row["cluster"]].append(row)
    available = {f"{CELL_NAMES[c]} {s}": len(pools.get((c, s), {})) for c in range(len(CELLS)) for s in STRATA}

    rng = random.Random(f"X5:{seed}")
    drawn = allocate(pools, demands(n), rng)
    corpora = {e: _corpus_for(r, corpus_dir) for e, r in pinned.items()}
    sessions = {e: _Sessions(c) for e, c in corpora.items()}
    rng.shuffle(drawn)                                   # file order carries no stratum
    ids = _item_ids(len(drawn), rng)
    items, key = [], {}
    for item_id, (slot, row) in zip(ids, drawn):
        exp_id, condition = CELLS[slot.cell]
        shown, verdict = build_item(pinned[exp_id], condition, row, sessions[exp_id])
        items.append({"item": item_id, **shown})
        key[item_id] = {
            "cell": CELL_NAMES[slot.cell], "stratum": slot.stratum, "calibration": slot.calibration,
            "experiment": exp_id, "run": pinned[exp_id].address, "condition": condition,
            "session": row["session"], "wazuh_alert_id": row["wazuh_alert_id"], "repeat": row["repeat"],
            "cluster": row["cluster"], "cache_key": verdict["cache_key"],
            **{f: row.get(f) for f in ("is_attack", "truth_label", "truth_coarse", "answer_label", "fine",
                                       "coarse", "disposition", "disposition_outcome", "confidence",
                                       "severity", "severity_outcome")}}
    calibration = [i["item"] for i in items if key[i["item"]]["calibration"]]

    counts = defaultdict(int)
    for slot, _ in drawn:
        counts[(CELL_NAMES[slot.cell], "calibration" if slot.calibration else slot.stratum)] += 1
    summary = {"batch": batch_id, "items": len(items), "analysed": n, "calibration": len(calibration),
               "seed": seed, "runs": {e: r.address for e, r in pinned.items()},
               "counts": {f"{c} {s}": v for (c, s), v in sorted(counts.items())},
               "available": available, "path": None}
    if dry_run:
        return summary
    key_doc = {"batch": batch_id, "made_by": "cjp rating make-batch", "made_with_code": runs.git_describe(),
               "seed": seed, "n": n, "cells": [{"name": nm, "experiment": e, "condition": c}
                                              for nm, (e, c) in zip(CELL_NAMES, CELLS)],
               "strata": list(STRATA), "runs": summary["runs"],
               "corpus": {e: {"id": c.id, "sha256": c.sha256} for e, c in corpora.items()},
               "available_clusters": available, "items": key}
    summary["path"] = rating.create_batch(batch_id, items, key_doc, calibration, root=root)
    return summary
