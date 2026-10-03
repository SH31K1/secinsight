from __future__ import annotations

import os
from functools import lru_cache


class Settings:
    database_url: str = os.environ.get(
        "DATABASE_URL", "postgresql+psycopg://secinsight:secinsight@localhost:5432/secinsight"
    )
    cors_origins: list[str] = os.environ.get("CORS_ORIGINS", "http://localhost:5173,http://localhost:3000").split(",")
    upload_dir: str = os.environ.get("UPLOAD_DIR", "/tmp/secinsight_uploads")
    reports_dir: str = os.environ.get("REPORTS_DIR", "/tmp/secinsight_reports")
    anthropic_api_key: str | None = os.environ.get("ANTHROPIC_API_KEY")


@lru_cache
def get_settings() -> Settings:
    return Settings()
