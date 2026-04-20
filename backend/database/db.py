"""Database session and engine setup."""

from __future__ import annotations

import os
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

PROJECT_ROOT = Path(__file__).resolve().parents[2]
default_root = os.environ.get("PRIVACY_ANALYZER_DB_ROOT") or os.environ.get("TEMP") or str(PROJECT_ROOT / "data")
DEFAULT_DB_DIR = Path(default_root) / "AIBrowserPrivacyAnalyzer"
DEFAULT_DB_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = Path(os.environ.get("PRIVACY_ANALYZER_DB_PATH", str(DEFAULT_DB_DIR / "privacy_analyzer.db")))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
DATABASE_URL = f"sqlite:///{DB_PATH.as_posix()}"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
