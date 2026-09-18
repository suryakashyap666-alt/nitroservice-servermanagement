from __future__ import annotations

from typing import Any, Dict, Literal, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.server_guard import ServerGuard

router = APIRouter(prefix="/api/v1/server-guard", tags=["server-management"])
guard: Optional[ServerGuard] = None


class DetectionRequest(BaseModel):
    server_id: str = Field(..., min_length=1)
    subject_id: str = Field(..., min_length=1)
    category: Literal["cheat", "scam", "screen"]
    evidence: Dict[str, Any] = Field(default_factory=dict)


class VerificationRequest(BaseModel):
    evidence: Dict[str, Any] = Field(default_factory=dict)


class BanRequest(BaseModel):
    moderator_id: str = Field(..., min_length=1)


class ServerCheckRequest(BaseModel):
    server_id: str = Field(..., min_length=1)
    config: Dict[str, Any] = Field(default_factory=dict)


def configure(server_guard: ServerGuard) -> None:
    global guard
    guard = server_guard


def _service() -> ServerGuard:
    if guard is None:
        raise HTTPException(status_code=503, detail="Server guard is not initialized")
    return guard


@router.post("/detect")
def detect(payload: DetectionRequest) -> Dict[str, Any]:
    if payload.category == "screen" and payload.evidence.get("screen_consent") is not True:
        raise HTTPException(status_code=400, detail="Explicit screen_consent is required for screen checks")
    case = _service().detect(payload.server_id, payload.subject_id, payload.category, payload.evidence)
    return {"ok": True, "action": "warning", "case": case}


@router.post("/cases/{case_id}/verify")
def verify(case_id: str, payload: VerificationRequest) -> Dict[str, Any]:
    try:
        case = _service().verify(case_id, payload.evidence)
    except KeyError:
        raise HTTPException(status_code=404, detail="Moderation case not found")
    return {"ok": True, "action": case["state"], "case": case}


@router.get("/cases/{case_id}")
def get_case(case_id: str) -> Dict[str, Any]:
    case = _service().get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Moderation case not found")
    return {"ok": True, "case": case}


@router.post("/cases/{case_id}/ban")
def ban(case_id: str, payload: BanRequest) -> Dict[str, Any]:
    try:
        case = _service().ban(case_id, payload.moderator_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Moderation case not found")
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return {"ok": True, "action": "banned", "case": case}


@router.post("/check-server")
def check_server(payload: ServerCheckRequest) -> Dict[str, Any]:
    return {"ok": True, "check": _service().inspect_server(payload.server_id, payload.config)}