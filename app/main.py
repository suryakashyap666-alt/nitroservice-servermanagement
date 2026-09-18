from __future__ import annotations

import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.health import router as health_v1_router
from app.api.server_guard import configure as configure_server_guard
from app.api.server_guard import router as server_guard_router
from app.server_guard import build_guard

DATA_DIR = os.environ.get("NITRO_DATA_DIR") or str(BASE_DIR / "data")
os.makedirs(DATA_DIR, exist_ok=True)
SERVER_GUARD = build_guard(DATA_DIR)
configure_server_guard(SERVER_GUARD)

app = FastAPI(
    title="Nitro Server Management AI",
    version="1.0.0",
    description="Evidence-first server monitoring and moderation service.",
    docs_url="/docs",
    redoc_url="/redoc",
)

ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.environ.get(
        "WEB_CLIENT_ORIGIN",
        "",
    ).split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS if "*" not in ALLOWED_ORIGINS else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount server-management API routers.
app.include_router(health_v1_router)
app.include_router(server_guard_router)


@app.get("/")
def root() -> dict:
    return {
        "service": "Nitro Server Management AI",
        "status": "online",
        "version": "1.0.0",
        "endpoints": {
            "health": "GET /api/v1/health",
            "detect": "POST /api/v1/server-guard/detect",
            "verify": "POST /api/v1/server-guard/cases/{case_id}/verify",
            "ban": "POST /api/v1/server-guard/cases/{case_id}/ban",
            "server_check": "POST /api/v1/server-guard/check-server",
            "docs": "GET /docs",
        },
    }


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "service": "nitro-server-management-ai",
        "version": "1.0.0",
        "engine": "Server Guard",
    }