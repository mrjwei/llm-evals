"""
The Results page's API (Plan P6.7): a read-only view of the run registry,
data/runs/<experiment>/<run>/, and the pins in results/canonical.yaml. It is
the same data INDEX.md is made from (runs.render_index), read live.

    GET /api/runs                                   every run, with its pins; the
                                                    experiments and RQs to filter by
    GET /api/runs/{experiment}/{run}                one run: run.json's facts and its
                                                    conditions
    GET /api/runs/{experiment}/{run}/report?doc=    one report.md as text (the run's, or
                                                    conditions/<c>/report.md)
    GET /api/runs/{experiment}/{run}/files/{path}   a chart (.png) a report shows

Nothing here writes. Only report.md files and PNGs inside the run's own
folder are served: no scores, verdicts, cache entries or paths outside it.
"""

import re
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from cjp import config, runs

router = APIRouter(prefix="/api/runs")

_EXPERIMENT_DIR = re.compile(r"[A-Z]\d+(-[a-z0-9]+)*")
_RUN_ID = re.compile(r"\d{4}-\d{2}-\d{2}T\d{4}_[0-9a-f]{6}")
SUMMARY = ("run_id", "experiment", "experiment_slug", "question", "rq", "status", "headline", "error",
           "superseded_by", "git_describe", "created_at", "finished_at", "model", "kind", "reps")


def _summary(run: runs.Run, by_run: dict[str, list[str]]) -> dict:
    m = run.meta
    return {"address": run.address, **{k: m.get(k) for k in SUMMARY},
            "corpus": (m.get("corpus") or {}).get("id"),
            "canonical": sorted(by_run.get(run.address, [])),
            "has_report": (run.path / "report.md").is_file()}


def _pins() -> tuple[dict, dict[str, list[str]]]:
    doc = runs.load_canonical_doc(config.CANONICAL_FILE)
    by_run: dict[str, list[str]] = {}
    for key, pin in (doc.get("pins") or {}).items():
        by_run.setdefault((pin or {}).get("run", ""), []).append(key)
    return doc, by_run


def _run(experiment: str, run_id: str) -> runs.Run:
    if not (_EXPERIMENT_DIR.fullmatch(experiment) and _RUN_ID.fullmatch(run_id)):
        raise HTTPException(404, f"no run {experiment}/{run_id}")
    try:
        return runs.find_run(f"{experiment}/{run_id}", config.RUNS_DIR)
    except LookupError as e:
        raise HTTPException(404, str(e)) from None


def _inside(run: runs.Run, rel: str, suffix: str) -> Path:
    """A file in the run's folder with this suffix, or 404."""
    root = run.path.resolve()
    path = (root / rel).resolve()
    if not rel or path.suffix != suffix or not path.is_relative_to(root) or not path.is_file():
        raise HTTPException(404, f"{run.address} has no {rel or 'file'}")
    return path


@router.get("")
def list_runs() -> dict:
    """Newest first. Superseded and failed runs are listed too, with their
    status, as INDEX.md lists them."""
    doc, by_run = _pins()
    all_runs = [_summary(r, by_run) for r in runs.list_runs(config.RUNS_DIR)]
    all_runs.sort(key=lambda r: r["created_at"] or "", reverse=True)
    pins = doc.get("pins") or {}
    known = {r["address"] for r in all_runs}
    return {"runs": all_runs,
            "experiments": sorted({r["experiment"] for r in all_runs}),
            "rqs": sorted({q for r in all_runs for q in r["rq"] or []}),
            "figures": [{"key": k, "title": (f or {}).get("title"), "from": (f or {}).get("from") or []}
                        for k, f in (doc.get("figures") or {}).items()],
            "pin_problems": sorted(k for k, p in pins.items() if (p or {}).get("run") not in known)}


@router.get("/{experiment}/{run_id}")
def get_run(experiment: str, run_id: str) -> dict:
    run = _run(experiment, run_id)
    _, by_run = _pins()
    m = run.meta
    conditions = [{"id": c, "has_report": (run.path / "conditions" / c / "report.md").is_file()}
                  for c in m.get("conditions") or []]
    return {**_summary(run, by_run), "conditions": conditions,
            "corpus_sha256": (m.get("corpus") or {}).get("sha256"), "git_sha": m.get("git_sha"),
            "prompt_hash": m.get("prompt_hash"), "cache": m.get("cache"), "resumes": m.get("resumes") or []}


@router.get("/{experiment}/{run_id}/report")
def get_report(experiment: str, run_id: str, doc: str = "report.md") -> dict:
    run = _run(experiment, run_id)
    if Path(doc).name != "report.md":
        raise HTTPException(404, f"{run.address} has no {doc}")
    path = _inside(run, doc, ".md")
    return {"address": run.address, "doc": path.relative_to(run.path.resolve()).as_posix(),
            "markdown": path.read_text()}


@router.get("/{experiment}/{run_id}/files/{rel:path}")
def get_file(experiment: str, run_id: str, rel: str) -> FileResponse:
    return FileResponse(_inside(_run(experiment, run_id), rel, ".png"), media_type="image/png")
