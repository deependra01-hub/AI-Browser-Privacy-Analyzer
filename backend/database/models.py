"""SQLAlchemy models for privacy analysis."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


class RequestLog(Base):
    __tablename__ = "requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    website: Mapped[str] = mapped_column(String(255), index=True)
    page_url: Mapped[str] = mapped_column(Text)
    request_url: Mapped[str] = mapped_column(Text)
    domain: Mapped[str] = mapped_column(String(255), index=True)
    method: Mapped[str] = mapped_column(String(16), default="GET")
    cookies_present: Mapped[bool] = mapped_column(Boolean, default=False)
    cookie_header: Mapped[str | None] = mapped_column(Text, nullable=True)
    tracker_status: Mapped[str] = mapped_column(String(64), default="safe")
    behavior_profile: Mapped[str] = mapped_column(String(128), default="normal")
    third_party: Mapped[bool] = mapped_column(Boolean, default=False)
    sensitive_data: Mapped[bool] = mapped_column(Boolean, default=False)
    sensitive_indicators: Mapped[str | None] = mapped_column(Text, nullable=True)
    analysis_reason: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(64), default="chrome_extension")
    risk_level: Mapped[str] = mapped_column(String(16), default="low")
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)


class DomainProfile(Base):
    __tablename__ = "domains"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    domain: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    status: Mapped[str] = mapped_column(String(64), default="safe")
    reason: Mapped[str] = mapped_column(Text, default="")
    profile: Mapped[str] = mapped_column(String(128), default="normal")
    request_count: Mapped[int] = mapped_column(Integer, default=0)
    requests_per_minute: Mapped[int] = mapped_column(Integer, default=0)
    sites_detected_on: Mapped[int] = mapped_column(Integer, default=1)
    cookie_usage_count: Mapped[int] = mapped_column(Integer, default=0)
    repetition_pattern: Mapped[str] = mapped_column(String(64), default="sporadic")
    anomaly_score: Mapped[float] = mapped_column(Float, default=0.0)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class WebsiteScore(Base):
    __tablename__ = "website_scores"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    website: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    category: Mapped[str] = mapped_column(String(64), default="Low Risk")
    tracker_count: Mapped[int] = mapped_column(Integer, default=0)
    sensitive_hits: Mapped[int] = mapped_column(Integer, default=0)
    third_party_count: Mapped[int] = mapped_column(Integer, default=0)
    aggressive_domain_count: Mapped[int] = mapped_column(Integer, default=0)
    request_frequency: Mapped[int] = mapped_column(Integer, default=0)
    total_requests: Mapped[int] = mapped_column(Integer, default=0)
    last_updated: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    website: Mapped[str] = mapped_column(String(255), index=True)
    domain: Mapped[str] = mapped_column(String(255), index=True)
    message: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
