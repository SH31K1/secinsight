from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from secinsight_core.parsers.base import load_all_parsers

from app.api import routes_compare, routes_reports, routes_scans
from app.config import get_settings
from app.db import Base, engine

load_all_parsers()
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Auto-create tables on startup. For production, prefer Alembic migrations
    # (see backend/alembic/) instead of create_all.
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="SecInsight AI API",
    description="Backend API for parsing, scoring, comparing, and reporting on security scan output.",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(routes_scans.router)
app.include_router(routes_compare.router)
app.include_router(routes_reports.router)


@app.get("/api/health")
def health():
    return {"status": "ok"}
