"""
The Triage page's job API (Plan P6.2): `/api/triage/*` over cjp.triage_jobs.

    GET  /api/triage/sources              what the source picker can offer
    POST /api/triage/jobs                 capture a source, plan and estimate; spends nothing
    GET  /api/triage/jobs                 every job, newest first
    GET  /api/triage/jobs/{id}            one job: status, progress, estimate, actual cost
    POST /api/triage/jobs/{id}/estimate   estimate what is left again (after a stop or failure)
    POST /api/triage/jobs/{id}/start      {"max_calls": N}: run, or resume, in the background
    POST /api/triage/jobs/{id}/stop       stop after the call in flight

The queue and verdict view (Plan P6.3, cjp.triage_queue):

    GET  /api/triage/jobs/{id}/queue      lanes (queue, needs a human, pending), sorted by one
                                          format's answers; ?format= &lane= &label=
                                          &disposition= &source=
    GET  /api/triage/jobs/{id}/alerts/{alert_id}
                                          one alert in full: both answers, each with how often
                                          its confidence level was right in evaluation, and
                                          the instruction-like-text flag
    POST /api/triage/jobs/{id}/alerts/{alert_id}/feedback
                                          {"format", "verdict": agree|disagree|null, "note"}:
                                          product feedback only, never research data
    GET  /api/triage/jobs/{id}/export.csv and export.json   the verdicts, as a download

Every POST passes the app's guard (decision 013), so no other web page can
start a paid job. start needs `max_calls`, the paid calls the person saw in
the estimate and approved; a job that needs more is refused with 409.
"""

from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from cjp import triage_jobs, triage_queue

router = APIRouter(prefix="/api/triage")

Arm = Literal["S1-plain", "S2-body-in-url", "S3-body-field"]


class DemoSource(BaseModel):
    kind: Literal["demo"]
    corpus: str = "C1"
    session: str | None = None
    arm: Arm = "S1-plain"


class UploadSource(BaseModel):
    kind: Literal["upload"]
    content: str
    filename: str = "alerts.jsonl"
    ingest_log: str | None = None


class LiveSource(BaseModel):
    kind: Literal["live"]
    minutes: int | None = None
    start: str | None = None
    end: str | None = None
    arm: Arm = "S1-plain"
    agent: str | None = None
    limit: int = triage_jobs.LIVE_DEFAULT_LIMIT


class NewJob(BaseModel):
    source: Annotated[DemoSource | UploadSource | LiveSource, Field(discriminator="kind")]
    bodies: bool = True
    formats: list[Literal["A", "B"]] = ["A", "B"]
    model: str | None = None


class Approval(BaseModel):
    max_calls: int = Field(ge=0)


class Feedback(BaseModel):
    format: Literal["A", "B"]
    verdict: Literal["agree", "disagree"] | None
    note: str | None = Field(default=None, max_length=triage_queue.MAX_NOTE)


def _call(fn, *args, **kwargs):
    """A cjp error as an HTTP status with its message: unknown job 404, busy
    or over budget 409, unusable input 400, an unreachable SIEM, VM or
    Claude API 502 with the fix."""
    from cjp.errors import explain
    try:
        return fn(*args, **kwargs)
    except triage_jobs.JobNotFound as e:
        raise HTTPException(404, str(e)) from None
    except triage_jobs.JobConflict as e:
        raise HTTPException(409, str(e)) from None
    except (ValueError, LookupError, FileNotFoundError) as e:
        raise HTTPException(400, str(e)) from None
    except Exception as e:
        if hint := explain(e):
            raise HTTPException(502, hint) from None
        raise


# Sync endpoints: FastAPI runs them in its thread pool, so a slow indexer
# query or count_tokens call never blocks the other requests.
@router.get("/sources")
def get_sources() -> dict:
    return _call(triage_jobs.sources)


@router.post("/jobs", status_code=201)
def create_job(job: NewJob) -> dict:
    return _call(triage_jobs.create, job.source.model_dump(), bodies=job.bodies,
                 formats=job.formats, model=job.model)


@router.get("/jobs")
def list_jobs() -> list[dict]:
    return triage_jobs.list_jobs()


@router.get("/jobs/{job_id}")
def get_job(job_id: str) -> dict:
    return _call(triage_jobs.load, job_id)


@router.post("/jobs/{job_id}/estimate")
def estimate_job(job_id: str) -> dict:
    return _call(triage_jobs.reestimate, job_id)


@router.post("/jobs/{job_id}/start", status_code=202)
def start_job(job_id: str, approval: Approval) -> dict:
    _call(triage_jobs.run_in_background, job_id, approval.max_calls)
    return triage_jobs.load(job_id)


@router.post("/jobs/{job_id}/stop", status_code=202)
def stop_job(job_id: str) -> dict:
    return _call(triage_jobs.stop, job_id)


@router.get("/jobs/{job_id}/queue")
def get_queue(job_id: str, format: Literal["A", "B"] | None = None, lane: str | None = None,
              label: str | None = None, disposition: str | None = None, source: str | None = None) -> dict:
    return _call(triage_queue.queue, job_id, format, lane=lane, label=label,
                 disposition=disposition, source=source)


@router.get("/jobs/{job_id}/alerts/{alert_id}")
def get_verdict(job_id: str, alert_id: str) -> dict:
    return _call(triage_queue.verdict, job_id, alert_id)


@router.post("/jobs/{job_id}/alerts/{alert_id}/feedback")
def post_feedback(job_id: str, alert_id: str, body: Feedback) -> dict:
    return _call(triage_queue.feedback, job_id, alert_id, body.format, body.verdict, body.note)


def _download(job_id: str, ext: str) -> dict:
    return {"Content-Disposition": f'attachment; filename="triage_{job_id}.{ext}"'}


@router.get("/jobs/{job_id}/export.csv")
def export_csv(job_id: str) -> Response:
    text = _call(triage_queue.export_csv, job_id)
    return Response(text, media_type="text/csv; charset=utf-8", headers=_download(job_id, "csv"))


@router.get("/jobs/{job_id}/export.json")
def export_json(job_id: str) -> JSONResponse:
    return JSONResponse(_call(triage_queue.export_json, job_id), headers=_download(job_id, "json"))
