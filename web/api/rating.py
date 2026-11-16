"""
The Rate page's API (Plan P6.6): `/api/rating/*` over cjp.rating.

    GET  /api/rating/rubric                              the rubric as raters see it (R1–R5)
    GET  /api/rating/batches                             every batch in data/ratings/, with each
                                                         rater's progress
    POST /api/rating/batches/{batch}/raters/{rater}      start or carry on as rater A or B: the
                                                         order, the scores so far, progress
    GET  /api/rating/batches/{batch}/raters/{rater}      the same, without starting
    GET  /api/rating/batches/{batch}/items/{item}        one item: the alert, its body, the answer
    POST /api/rating/batches/{batch}/raters/{rater}/items/{item}
                                                         {"R1": 4, "R5": "escalate", …}: save the
                                                         changed scores at once (autosave)

Nothing here reads a batch's key.json, so no route can tell a rater the
condition, model, format, ground truth or correctness of an item.
"""

from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict

from cjp import rating

router = APIRouter(prefix="/api/rating")
Rater = Literal["A", "B"]


class Scores(BaseModel):
    model_config = ConfigDict(extra="forbid")
    R1: int | None = None
    R2: int | None = None
    R3: int | None = None
    R4: int | None = None
    R5: str | None = None


def _call(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except rating.RatingNotFound as e:
        raise HTTPException(404, str(e)) from None
    except rating.RatingConflict as e:
        raise HTTPException(409, str(e)) from None
    except ValueError as e:
        raise HTTPException(400, str(e)) from None


@router.get("/rubric")
def get_rubric() -> dict:
    return rating.load_rubric()


@router.get("/batches")
def list_batches() -> list[dict]:
    return rating.list_batches()


@router.post("/batches/{batch_id}/raters/{rater}")
def start(batch_id: str, rater: Rater) -> dict:
    return _call(rating.start, batch_id, rater)


@router.get("/batches/{batch_id}/raters/{rater}")
def get_session(batch_id: str, rater: Rater) -> dict:
    return _call(rating.session, batch_id, rater)


@router.get("/batches/{batch_id}/items/{item_id}")
def get_item(batch_id: str, item_id: str) -> dict:
    return _call(rating.item, batch_id, item_id)


@router.post("/batches/{batch_id}/raters/{rater}/items/{item_id}")
def save(batch_id: str, rater: Rater, item_id: str, scores: Scores) -> dict:
    return _call(rating.save, batch_id, rater, item_id, scores.model_dump(exclude_unset=True))
