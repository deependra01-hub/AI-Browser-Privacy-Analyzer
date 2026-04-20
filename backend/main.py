"""FastAPI application for the browser privacy analyzer."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import desc, distinct, func, select
from sqlalchemy.orm import Session

from backend.analyzer import LocalIntelligenceEngine
from backend.analyzer.risk_scoring import derive_request_risk_types
from backend.analyzer.tracker_detection import classify_data_exposure, normalize_domain, summarize_sensitive_data
from backend.database.db import Base, engine, get_db
from backend.database.models import Alert, DomainProfile, RequestLog, WebsiteScore

Base.metadata.create_all(bind=engine)

app = FastAPI(title="AI-Based Browser Privacy Analyzer", version="1.0.0")
analysis_engine = LocalIntelligenceEngine()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_DIR = PROJECT_ROOT / "dashboard"
app.mount("/static", StaticFiles(directory=DASHBOARD_DIR), name="static")


class AnalyzeRequest(BaseModel):
    url: str = Field(..., description="Captured network request URL")
    domain: str | None = None
    method: str = "GET"
    cookies: str | None = None
    timestamp: str | None = None
    tab_url: str | None = None
    website: str | None = None
    source: str = "chrome_extension"


DbSession = Annotated[Session, Depends(get_db)]


def parse_timestamp(value: str | None) -> datetime:
    if not value:
        return datetime.utcnow()
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid timestamp format") from exc


def serialize_timestamp(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def website_from_payload(payload: AnalyzeRequest) -> str:
    for candidate in [payload.website, payload.tab_url]:
        domain = normalize_domain(candidate)
        if "." in domain or domain == "localhost":
            return domain
    return normalize_domain(payload.url)


def get_recent_domain_events(db: Session, domain: str, limit: int = 200) -> list[dict]:
    stmt = select(RequestLog).where(RequestLog.domain == domain).order_by(desc(RequestLog.timestamp)).limit(limit)
    records = db.execute(stmt).scalars().all()
    return [
        {
            "website": record.website,
            "timestamp": record.timestamp.isoformat(),
            "cookies_present": record.cookies_present,
        }
        for record in records
    ]


def get_website_metrics(db: Session, website: str, domain: str) -> dict:
    one_minute_ago = datetime.utcnow() - timedelta(minutes=1)

    tracker_count = db.scalar(
        select(func.count(distinct(RequestLog.domain))).where(
            RequestLog.website == website,
            RequestLog.tracker_status.in_(["known tracker", "suspicious"]),
        )
    ) or 0
    sensitive_hits = db.scalar(
        select(func.count(RequestLog.id)).where(RequestLog.website == website, RequestLog.sensitive_data.is_(True))
    ) or 0
    third_party_count = db.scalar(
        select(func.count(distinct(RequestLog.domain))).where(
            RequestLog.website == website,
            RequestLog.third_party.is_(True),
        )
    ) or 0
    aggressive_domains = db.scalar(
        select(func.count(distinct(RequestLog.domain))).where(
            RequestLog.website == website,
            RequestLog.behavior_profile.in_(
                ["aggressive tracking", "cross-site tracking", "aggressive cross-site tracker"]
            ),
        )
    ) or 0
    request_frequency = db.scalar(
        select(func.count(RequestLog.id)).where(
            RequestLog.website == website,
            RequestLog.timestamp >= one_minute_ago,
        )
    ) or 0
    recent_domain_request_count = db.scalar(
        select(func.count(RequestLog.id)).where(
            RequestLog.domain == domain,
            RequestLog.timestamp >= one_minute_ago,
        )
    ) or 0
    total_requests = db.scalar(select(func.count(RequestLog.id)).where(RequestLog.website == website)) or 0

    return {
        "tracker_count": tracker_count,
        "sensitive_hits": sensitive_hits,
        "third_party_count": third_party_count,
        "aggressive_domains": aggressive_domains,
        "request_frequency": request_frequency,
        "recent_domain_request_count": recent_domain_request_count,
        "total_requests": total_requests,
    }


def upsert_domain_profile(
    db: Session,
    *,
    domain: str,
    detection: dict,
    behavior: dict,
    request_count: int,
    last_seen: datetime,
) -> None:
    profile = db.execute(select(DomainProfile).where(DomainProfile.domain == domain)).scalar_one_or_none()
    if profile is None:
        profile = DomainProfile(domain=domain)
        db.add(profile)

    profile.status = detection["status"]
    profile.reason = detection["reason"]
    profile.profile = behavior["profile"]
    profile.request_count = request_count
    profile.requests_per_minute = behavior["frequency"]
    profile.sites_detected_on = behavior["sites_detected_on"]
    profile.cookie_usage_count = behavior["cookie_usage"]
    profile.repetition_pattern = behavior["repetition_pattern"]
    profile.anomaly_score = behavior["anomaly_score"]
    profile.last_seen = last_seen


def upsert_website_score(
    db: Session,
    website: str,
    metrics: dict,
    website_risk: dict,
    last_seen: datetime,
) -> WebsiteScore:
    record = db.execute(select(WebsiteScore).where(WebsiteScore.website == website)).scalar_one_or_none()
    if record is None:
        record = WebsiteScore(website=website)
        db.add(record)

    record.risk_score = website_risk["risk_score"]
    record.category = website_risk["category"]
    record.tracker_count = metrics["tracker_count"]
    record.sensitive_hits = metrics["sensitive_hits"]
    record.third_party_count = metrics["third_party_count"]
    record.aggressive_domain_count = metrics["aggressive_domains"]
    record.request_frequency = metrics["request_frequency"]
    record.total_requests = metrics["total_requests"]
    record.last_updated = last_seen
    return record


def severity_from_request_risk(request_risk: dict) -> str:
    if request_risk["risk_level"] == "high":
        return "high"
    if request_risk["risk_level"] == "medium":
        return "medium"
    return "low"


def request_explanation_from_record(record: RequestLog) -> dict:
    indicators = [item.strip() for item in (record.sensitive_indicators or "").split(",") if item.strip()]
    detection = {
        "status": record.tracker_status,
        "third_party": record.third_party,
        "sensitive_indicators": indicators,
    }
    behavior = {"profile": record.behavior_profile}
    shared_data = summarize_sensitive_data(indicators, record.cookies_present)
    return {
        "risk_types": derive_request_risk_types(
            detection=detection,
            behavior=behavior,
            cookies_present=record.cookies_present,
        ),
        "data_shared": shared_data,
    }


def aggregate_website_explanation(db: Session, website: str) -> dict:
    records = db.execute(
        select(RequestLog).where(RequestLog.website == website).order_by(desc(RequestLog.timestamp)).limit(200)
    ).scalars().all()

    risk_types: set[str] = set()
    data_shared: set[str] = set()
    tracker_domains: set[str] = set()

    for record in records:
        explanation = request_explanation_from_record(record)
        risk_types.update(explanation["risk_types"])
        data_shared.update(explanation["data_shared"])
        if record.tracker_status in {"known tracker", "suspicious"}:
            tracker_domains.add(record.domain)

    if len(risk_types) > 1 and "Low observable privacy risk" in risk_types:
        risk_types.discard("Low observable privacy risk")

    return {
        "risk_types": sorted(risk_types)[:6],
        "data_shared": sorted(data_shared)[:6],
        "tracker_domains": sorted(tracker_domains)[:8],
    }


@app.get("/")
def serve_dashboard() -> FileResponse:
    return FileResponse(DASHBOARD_DIR / "index.html")


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "privacy-analyzer"}


@app.post("/analyze")
def analyze_request(payload: AnalyzeRequest, db: DbSession) -> dict:
    request_time = parse_timestamp(payload.timestamp)
    domain = normalize_domain(payload.domain or payload.url)
    website = website_from_payload(payload)

    recent_domain_events = get_recent_domain_events(db, domain)
    website_metrics = get_website_metrics(db, website, domain)
    analysis = analysis_engine.analyze_request(
        request_url=payload.url,
        domain=domain,
        website=website,
        method=payload.method,
        cookies=payload.cookies,
        recent_domain_events=recent_domain_events,
        website_metrics=website_metrics,
    )
    risk_types = derive_request_risk_types(
        detection=analysis["detection"],
        behavior=analysis["behavior"],
        cookies_present=bool(payload.cookies),
    )
    data_shared = summarize_sensitive_data(
        analysis["detection"]["sensitive_indicators"],
        bool(payload.cookies),
    )
    data_exposure = classify_data_exposure(
        analysis["detection"]["sensitive_indicators"],
        bool(payload.cookies),
    )

    db.add(
        RequestLog(
            website=website,
            page_url=payload.tab_url or payload.url,
            request_url=payload.url,
            domain=domain,
            method=payload.method,
            cookies_present=bool(payload.cookies),
            cookie_header=payload.cookies,
            tracker_status=analysis["detection"]["status"],
            behavior_profile=analysis["behavior"]["profile"],
            third_party=analysis["detection"]["third_party"],
            sensitive_data=bool(data_exposure["material_markers"]),
            sensitive_indicators=", ".join(analysis["detection"]["sensitive_indicators"]) or None,
            analysis_reason=analysis["detection"]["reason"],
            source=payload.source,
            risk_level=analysis["request_risk"]["risk_level"],
            timestamp=request_time,
        )
    )
    db.flush()

    request_count = db.scalar(select(func.count(RequestLog.id)).where(RequestLog.domain == domain)) or 0
    upsert_domain_profile(
        db,
        domain=domain,
        detection=analysis["detection"],
        behavior=analysis["behavior"],
        request_count=request_count,
        last_seen=request_time,
    )

    refreshed_metrics = get_website_metrics(db, website, domain)
    website_risk = analysis_engine.analyze_request(
        request_url=payload.url,
        domain=domain,
        website=website,
        method=payload.method,
        cookies=payload.cookies,
        recent_domain_events=recent_domain_events,
        website_metrics=refreshed_metrics,
    )["website_risk"]
    website_score = upsert_website_score(db, website, refreshed_metrics, website_risk, request_time)

    created_alerts: list[str] = []
    for message in analysis["alerts"]:
        created_alerts.append(message)
        db.add(
            Alert(
                website=website,
                domain=domain,
                message=message,
                severity=severity_from_request_risk(analysis["request_risk"]),
                timestamp=request_time,
            )
        )

    if website_score.category == "High Risk":
        message = f"Website {website} is currently High Risk"
        created_alerts.append(message)
        db.add(Alert(website=website, domain=domain, message=message, severity="high", timestamp=request_time))

    db.commit()

    return {
        "website": website,
        "domain": domain,
        "tracker_detection": analysis["detection"],
        "behavior_profile": analysis["behavior"],
        "request_risk": analysis["request_risk"],
        "website_risk": website_risk,
        "risk_types": risk_types,
        "data_shared": data_shared,
        "alerts": created_alerts,
        "stored": True,
    }


@app.get("/api/summary")
def api_summary(db: DbSession) -> dict:
    total_requests = db.scalar(select(func.count(RequestLog.id))) or 0
    total_websites = db.scalar(select(func.count(WebsiteScore.id))) or 0
    high_risk_websites = db.scalar(
        select(func.count(WebsiteScore.id)).where(WebsiteScore.category == "High Risk")
    ) or 0
    trackers_detected = db.scalar(
        select(func.count(distinct(RequestLog.domain))).where(
            RequestLog.tracker_status.in_(["known tracker", "suspicious"])
        )
    ) or 0
    latest_alert = db.execute(select(Alert).order_by(desc(Alert.timestamp)).limit(1)).scalar_one_or_none()

    return {
        "total_requests": total_requests,
        "total_websites": total_websites,
        "high_risk_websites": high_risk_websites,
        "trackers_detected": trackers_detected,
        "latest_alert": latest_alert.message if latest_alert else "No alerts yet",
    }


@app.get("/api/websites")
def api_websites(db: DbSession) -> list[dict]:
    rows = db.execute(select(WebsiteScore).order_by(desc(WebsiteScore.last_updated))).scalars().all()
    return [
        (
            lambda explanation: {
                "website": row.website,
                "risk_score": row.risk_score,
                "category": row.category,
                "tracker_count": row.tracker_count,
                "sensitive_hits": row.sensitive_hits,
                "third_party_count": row.third_party_count,
                "aggressive_domain_count": row.aggressive_domain_count,
                "request_frequency": row.request_frequency,
                "total_requests": row.total_requests,
                "risk_types": explanation["risk_types"],
                "data_shared": explanation["data_shared"],
                "tracker_domains": explanation["tracker_domains"],
                "last_updated": serialize_timestamp(row.last_updated),
            }
        )(aggregate_website_explanation(db, row.website))
        for row in rows
    ]


@app.get("/api/domains")
def api_domains(db: DbSession) -> list[dict]:
    rows = db.execute(select(DomainProfile).order_by(desc(DomainProfile.anomaly_score))).scalars().all()
    return [
        {
            "domain": row.domain,
            "status": row.status,
            "profile": row.profile,
            "request_count": row.request_count,
            "requests_per_minute": row.requests_per_minute,
            "sites_detected_on": row.sites_detected_on,
            "cookie_usage_count": row.cookie_usage_count,
            "repetition_pattern": row.repetition_pattern,
            "anomaly_score": row.anomaly_score,
            "reason": row.reason,
            "risk_types": derive_request_risk_types(
                detection={
                    "status": row.status,
                    "third_party": row.sites_detected_on > 1,
                    "sensitive_indicators": [],
                },
                behavior={"profile": row.profile},
                cookies_present=row.cookie_usage_count > 0,
            ),
            "last_seen": serialize_timestamp(row.last_seen),
        }
        for row in rows[:20]
    ]


@app.get("/api/alerts")
def api_alerts(db: DbSession) -> list[dict]:
    rows = db.execute(select(Alert).order_by(desc(Alert.timestamp)).limit(25)).scalars().all()
    return [
        {
            "website": row.website,
            "domain": row.domain,
            "message": row.message,
            "severity": row.severity,
            "timestamp": serialize_timestamp(row.timestamp),
        }
        for row in rows
    ]


@app.get("/api/websites/{website}")
def api_website_details(website: str, db: DbSession) -> dict:
    website_score = db.execute(select(WebsiteScore).where(WebsiteScore.website == website)).scalar_one_or_none()
    if website_score is None:
        raise HTTPException(status_code=404, detail="Website not found")

    recent_requests = db.execute(
        select(RequestLog).where(RequestLog.website == website).order_by(desc(RequestLog.timestamp)).limit(20)
    ).scalars().all()

    explanation = aggregate_website_explanation(db, website)

    return {
        "website": website,
        "score": {
            "risk_score": website_score.risk_score,
            "category": website_score.category,
            "tracker_count": website_score.tracker_count,
            "sensitive_hits": website_score.sensitive_hits,
            "third_party_count": website_score.third_party_count,
            "aggressive_domain_count": website_score.aggressive_domain_count,
            "total_requests": website_score.total_requests,
            "last_updated": serialize_timestamp(website_score.last_updated),
            "risk_types": explanation["risk_types"],
            "data_shared": explanation["data_shared"],
            "tracker_domains": explanation["tracker_domains"],
        },
        "requests": [
            (
                lambda req_explanation: {
                    "domain": item.domain,
                    "request_url": item.request_url,
                    "tracker_status": item.tracker_status,
                    "behavior_profile": item.behavior_profile,
                    "risk_level": item.risk_level,
                    "risk_types": req_explanation["risk_types"],
                    "data_shared": req_explanation["data_shared"],
                    "analysis_reason": item.analysis_reason,
                    "timestamp": serialize_timestamp(item.timestamp),
                }
            )(request_explanation_from_record(item))
            for item in recent_requests
        ],
    }
