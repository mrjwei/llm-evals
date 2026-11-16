"""
X5 expert-rating analysis (Plan P7.3, METHODS §7; decisions 021, 022): joins
each rater's scores with the batch's key and computes what METHODS §7 names.
`cjp results build` calls it for any figure whose `from` names a rating
batch (data/ratings/<batch>/) rather than an experiment.

    agreement   quadratic-weighted κ per R1–R4, unweighted κ for R5, between
                raters A and B. With one complete rater it is not computable,
                and the row says so (METHODS §7 single-rater fallback)
    means       mean R1–R4 per cell (condition and format), per stratum
                (the item's scored outcome), per stated confidence, and per
                cell × stratum and confidence × stratum, each with a 95%
                item-level bootstrap interval
    R5          how often the rater's own decision matches the LLM's
                disposition and the expected disposition (ground truth), next
                to the LLM's own match on the same items, plus the cross-tabs

The 6 calibration items are left out. Every analysed item is a distinct
request cluster (decision 021 rule 4), so the item-level bootstrap is the
cluster bootstrap of METHODS §6. With two raters, an item's score is the mean
of the two. Means are per stratum or per cell, never pooled as if the batch
were representative: the strata are equal-sized by design (decision 021).

This is the only rating code besides `cjp.rating_batch` that reads key.json,
and it runs only once the rating is done; `cjp.rating` (the app and the pack)
never does.
"""

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from cjp import config, rating
from cjp.evaluate.metrics import cluster_bootstrap_ci, cohens_kappa
from cjp.evaluate.score import EXPECTED_DISPOSITION
from cjp.rating import CHOICE_ITEM, SCALE_ITEMS
from cjp.rating_batch import CELL_NAMES, STRATA

CONFIDENCE = ("low", "medium", "high")
DISPOSITIONS = ("escalate", "dismiss_false_positive", "needs_more_info")
SINGLE_RATER = "not computable: one complete rater (METHODS §7 single-rater fallback, decision 022)"


def is_batch(name: str, root: Path | None = None) -> bool:
    try:
        rating.batch_dir(name, root)
        return True
    except rating.RatingNotFound:
        return False


# ── statistics ───────────────────────────────────────────────────────────────
def weighted_kappa(a: list[int], b: list[int], low: int, high: int) -> float | None:
    """Cohen's κ with quadratic weights over the ordered scale low..high."""
    n = len(a)
    if n == 0 or n != len(b):
        return None
    k = high - low + 1
    obs = [[0.0] * k for _ in range(k)]
    for x, y in zip(a, b):
        obs[x - low][y - low] += 1 / n
    row = [sum(r) for r in obs]
    col = [sum(obs[i][j] for i in range(k)) for j in range(k)]
    w = [[((i - j) / (k - 1)) ** 2 for j in range(k)] for i in range(k)]
    disagree_obs = sum(w[i][j] * obs[i][j] for i in range(k) for j in range(k))
    disagree_exp = sum(w[i][j] * row[i] * col[j] for i in range(k) for j in range(k))
    if disagree_exp == 0:
        return 1.0 if disagree_obs == 0 else 0.0
    return 1 - disagree_obs / disagree_exp


def mean_ci(values: list[float], boot: dict) -> dict:
    """Mean with its percentile bootstrap interval, resampling items."""
    ci = cluster_bootstrap_ci([(v, 1) for v in values], **boot)
    return {"value": sum(values) / len(values) if values else None,
            "ci_low": ci[0] if ci else None, "ci_high": ci[1] if ci else None, "n": len(values)}


def share_ci(hits: list[bool], boot: dict) -> dict:
    out = mean_ci([1.0 if h else 0.0 for h in hits], boot)
    out["num"] = sum(hits)
    return out


# ── the batch, joined with its key ───────────────────────────────────────────
@dataclass
class Rated:
    """One analysed item: what the key says about it and each rater's scores."""
    item: str
    cell: str
    stratum: str
    confidence: str | None
    llm: str | None                     # the LLM's disposition
    expected: str                       # the expected disposition (ground truth)
    scores: dict[str, dict] = field(default_factory=dict)

    def score(self, item_id: str) -> float:
        vals = [s[item_id] for s in self.scores.values()]
        return sum(vals) / len(vals)


@dataclass
class RatingData:
    batch: rating.Batch
    key: dict
    raters: list[str]                   # complete raters only
    incomplete: list[str]
    items: list[Rated]
    rater_files: dict[str, dict]

    @property
    def single_rater(self) -> bool:
        return len(self.raters) < 2


def load(batch_id: str, root: Path | None = None) -> RatingData:
    batch = rating.Batch(batch_id, root)
    key = json.loads((batch.path / "key.json").read_text())
    docs = {r: batch.rater_doc(r) for r in rating.RATERS}
    docs = {r: d for r, d in docs.items() if d}
    every = [i["item"] for i in batch.items]
    complete = [r for r, d in docs.items() if all(rating.complete(d["ratings"].get(i)) for i in every)]
    items = []
    for item_id, k in key["items"].items():
        if k["calibration"]:
            continue
        items.append(Rated(item_id, k["cell"], k["stratum"], k.get("confidence"), k.get("disposition"),
                           EXPECTED_DISPOSITION[bool(k["is_attack"])],
                           {r: docs[r]["ratings"][item_id] for r in complete}))
    files = {}
    for r, d in docs.items():
        raw = batch.rater_path(r).read_bytes()
        files[r] = {"sha256": hashlib.sha256(raw).hexdigest(), "updated_at": d.get("updated_at"),
                    "via": d.get("via"), "rubric_sha256": d["rubric"]["sha256"], "complete": r in complete}
    return RatingData(batch, key, complete, [r for r in docs if r not in complete], items, files)


# ── the tables ───────────────────────────────────────────────────────────────
def agreement_rows(data: RatingData) -> list[dict]:
    rows = []
    for item_id in (*SCALE_ITEMS, CHOICE_ITEM):
        stat = "Cohen's kappa (unweighted)" if item_id == CHOICE_ITEM else "Cohen's kappa (quadratic weights)"
        row = {"rubric_item": item_id, "statistic": stat, "raters": "+".join(data.raters),
               "n": len(data.items), "value": None, "percent_agreement": None, "note": None}
        if data.single_rater:
            row["note"] = SINGLE_RATER
        else:
            a = [i.scores["A"][item_id] for i in data.items]
            b = [i.scores["B"][item_id] for i in data.items]
            row["value"] = (cohens_kappa(a, b) if item_id == CHOICE_ITEM
                            else weighted_kappa(a, b, 1, 5))
            row["percent_agreement"] = sum(x == y for x, y in zip(a, b)) / len(a)
        rows.append(row)
    return rows


def groupings(items: list[Rated]) -> list[tuple[str, str, list[Rated]]]:
    """(grouping, group, items) for every summary METHODS §7 asks for."""
    out = [("all", "all", items)]
    out += [("cell", c, [i for i in items if i.cell == c]) for c in CELL_NAMES]
    out += [("stratum", s, [i for i in items if i.stratum == s]) for s in STRATA]
    out += [("confidence", c, [i for i in items if i.confidence == c]) for c in CONFIDENCE]
    out += [("cell × stratum", f"{c} · {s}", [i for i in items if (i.cell, i.stratum) == (c, s)])
            for c in CELL_NAMES for s in STRATA]
    out += [("confidence × stratum", f"{c} · {s}", [i for i in items if (i.confidence, i.stratum) == (c, s)])
            for c in CONFIDENCE for s in STRATA]
    return [g for g in out if g[2]]


def mean_rows(data: RatingData, boot: dict) -> list[dict]:
    rows = []
    for grouping, group, members in groupings(data.items):
        for item_id in SCALE_ITEMS:
            rows.append({"grouping": grouping, "group": group, "rubric_item": item_id,
                         "raters": "+".join(data.raters),
                         **mean_ci([m.score(item_id) for m in members], boot)})
    return rows


def r5_rows(data: RatingData, boot: dict) -> tuple[list[dict], list[dict]]:
    """Agreement shares per rater and grouping, and the cross-tabs."""
    shares, crosstab = [], []
    for grouping, group, members in groupings(data.items):
        if grouping not in ("all", "cell", "stratum"):
            continue
        base = {"grouping": grouping, "group": group}
        shares.append({**base, "rater": "LLM", "comparison": "LLM disposition = expected",
                       **share_ci([m.llm == m.expected for m in members], boot)})
        for r in data.raters:
            own = [m.scores[r][CHOICE_ITEM] for m in members]
            shares.append({**base, "rater": r, "comparison": "rater R5 = LLM disposition",
                           **share_ci([o == m.llm for o, m in zip(own, members)], boot)})
            shares.append({**base, "rater": r, "comparison": "rater R5 = expected",
                           **share_ci([o == m.expected for o, m in zip(own, members)], boot)})
    for r in data.raters:
        for against, attr in (("LLM disposition", "llm"), ("expected", "expected")):
            for own in DISPOSITIONS:
                for other in DISPOSITIONS:
                    crosstab.append({"rater": r, "against": against, "rater_R5": own, "other": other,
                                     "items": sum(1 for m in data.items if m.scores[r][CHOICE_ITEM] == own
                                                  and getattr(m, attr) == other)})
    return shares, crosstab


def analyse(batch_id: str, boot: dict, root: Path | None = None) -> dict:
    data = load(batch_id, root)
    if not data.raters:
        return {"data": data}
    shares, crosstab = r5_rows(data, boot)
    return {"data": data, "agreement": agreement_rows(data), "means": mean_rows(data, boot),
            "r5": shares, "r5_crosstab": crosstab}


# ── as a source of `cjp results build` ───────────────────────────────────────
@dataclass
class BatchSource:
    """A rating batch named in a figure's `from`, in the shape results.Source has."""
    experiment: str
    root: Path
    _data: RatingData | None = None

    @property
    def data(self) -> RatingData:
        if self._data is None:
            self._data = load(self.experiment, self.root)
        return self._data

    def provenance(self) -> dict:
        d, k = self.data, self.data.key
        first = next(iter(k["corpus"].values()), {})
        return {"experiment": self.experiment, "kind": "rating", "batch": d.batch.id,
                "drawn_from": k["runs"], "corpus": first.get("id"), "corpus_sha256": first.get("sha256"),
                "git_describe": k.get("made_with_code"), "rubric": d.batch.meta["rubric"],
                "raters": d.rater_files}

    def footer(self) -> str:
        p = self.provenance()
        runs = ", ".join(f"{e} {run.split('/')[-1]}" for e, run in p["drawn_from"].items())
        who = ", ".join(self.data.raters) or "none complete"
        return (f"{self.experiment} rating batch · drawn from {runs} · corpus {p['corpus']} "
                f"{(p['corpus_sha256'] or '?')[:8]} · rubric v{p['rubric']['version']} "
                f"{p['rubric']['sha256'][:8]} · rater(s) {who}"
                + (" (single-rater review)" if self.data.single_rater else ""))


def check_batch(name: str, pins: dict, root: Path | None = None) -> tuple[BatchSource | None, list[str]]:
    """The batch as a build source, and what is wrong with it: every rater
    file complete, at least one rater, each rater's rubric the current one,
    and the batch drawn from the runs that are pinned now."""
    root = Path(root or config.RATINGS_DIR)
    src = BatchSource(name, root)
    data = src.data
    problems = [f"{name}: rater {r} has not scored every item" for r in data.incomplete]
    if not data.raters:
        return None, problems + [f"{name}: no rater has finished the batch"]
    current = rating.load_rubric()["sha256"]
    problems += [f"{name}: rater {r} scored under rubric {f['rubric_sha256'][:8]}, not the current "
                 f"{current[:8]}" for r, f in data.rater_files.items() if f["rubric_sha256"] != current]
    for exp, run in data.key["runs"].items():
        pinned = (pins.get(exp) or {}).get("run")
        if pinned != run:
            problems.append(f"{name}: drawn from {exp} run {run}, but {exp}'s pin is {pinned}")
    return src, problems
