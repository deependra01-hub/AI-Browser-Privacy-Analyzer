"""Recalculate stored request classifications, website scores, domain profiles, and alerts."""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from pathlib import Path
import sys

from sqlalchemy import select

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.analyzer import LocalIntelligenceEngine
from backend.analyzer.risk_scoring import calculate_website_risk
from backend.analyzer.tracker_detection import normalize_domain
from backend.database.db import SessionLocal
from backend.database.models import Alert, DomainProfile, RequestLog, WebsiteScore

AGGRESSIVE_PROFILES = {"aggressive tracking", "cross-site tracking", "aggressive cross-site tracker"}


def severity_from_risk_level(risk_level: str) -> str:
    if risk_level == "high":
        return "high"
    if risk_level == "medium":
        return "medium"
    return "low"


def main() -> None:
    db = SessionLocal()
    engine = LocalIntelligenceEngine()

    try:
        requests = db.execute(select(RequestLog).order_by(RequestLog.timestamp, RequestLog.id)).scalars().all()
        db.query(Alert).delete()
        db.query(DomainProfile).delete()
        db.query(WebsiteScore).delete()
        db.flush()

        processed_domain_events: dict[str, list[dict]] = defaultdict(list)
        domain_profiles: dict[str, DomainProfile] = {}
        website_scores: dict[str, WebsiteScore] = {}
        website_state: dict[str, dict] = defaultdict(
            lambda: {
                "tracker_domains": set(),
                "third_party_domains": set(),
                "aggressive_domains": set(),
                "material_data_hits": 0,
                "timestamps": [],
                "total_requests": 0,
                "category": "Low Risk",
            }
        )

        for record in requests:
            page_candidate = normalize_domain(record.website or record.page_url or "")
            website = page_candidate if "." in page_candidate or page_candidate == "localhost" else normalize_domain(record.request_url)
            domain = normalize_domain(record.domain or record.request_url)
            record.website = website
            record.domain = domain

            now = record.timestamp
            recent_domain_events = processed_domain_events[domain]
            recent_domain_request_count = sum(
                1 for item in recent_domain_events if item["timestamp"] >= now - timedelta(minutes=1)
            )

            state = website_state[website]
            state["timestamps"] = [ts for ts in state["timestamps"] if ts >= now - timedelta(minutes=1)]
            website_metrics = {
                "tracker_count": len(state["tracker_domains"]),
                "sensitive_hits": state["material_data_hits"],
                "third_party_count": len(state["third_party_domains"]),
                "aggressive_domains": len(state["aggressive_domains"]),
                "request_frequency": len(state["timestamps"]),
                "recent_domain_request_count": recent_domain_request_count,
                "total_requests": state["total_requests"],
            }

            analysis = engine.analyze_request(
                request_url=record.request_url,
                domain=domain,
                website=website,
                method=record.method,
                cookies=record.cookie_header,
                recent_domain_events=[
                    {
                        "website": item["website"],
                        "timestamp": item["timestamp"].isoformat(),
                        "cookies_present": item["cookies_present"],
                    }
                    for item in recent_domain_events
                ],
                website_metrics=website_metrics,
            )

            detection = analysis["detection"]
            behavior = analysis["behavior"]
            request_risk = analysis["request_risk"]

            record.tracker_status = detection["status"]
            record.behavior_profile = behavior["profile"]
            record.third_party = detection["third_party"]
            record.sensitive_data = bool(detection["material_data"])
            record.sensitive_indicators = ", ".join(detection["sensitive_indicators"]) or None
            record.analysis_reason = detection["reason"]
            record.risk_level = request_risk["risk_level"]

            processed_domain_events[domain].append(
                {
                    "website": website,
                    "timestamp": now,
                    "cookies_present": record.cookies_present,
                }
            )

            state["timestamps"].append(now)
            state["total_requests"] += 1
            if record.tracker_status in {"known tracker", "suspicious"}:
                state["tracker_domains"].add(domain)
            if record.third_party:
                state["third_party_domains"].add(domain)
            if record.behavior_profile in AGGRESSIVE_PROFILES:
                state["aggressive_domains"].add(domain)
            if record.sensitive_data:
                state["material_data_hits"] += 1

            refreshed_metrics = {
                "tracker_count": len(state["tracker_domains"]),
                "sensitive_hits": state["material_data_hits"],
                "third_party_count": len(state["third_party_domains"]),
                "aggressive_domains": len(state["aggressive_domains"]),
                "request_frequency": len([ts for ts in state["timestamps"] if ts >= now - timedelta(minutes=1)]),
                "total_requests": state["total_requests"],
            }
            website_risk = calculate_website_risk(
                trackers=refreshed_metrics["tracker_count"],
                sensitive_hits=refreshed_metrics["sensitive_hits"],
                request_frequency=refreshed_metrics["request_frequency"],
                third_party=refreshed_metrics["third_party_count"],
                aggressive_domains=refreshed_metrics["aggressive_domains"],
            )

            domain_profile = domain_profiles.get(domain)
            if domain_profile is None:
                domain_profile = DomainProfile(domain=domain)
                domain_profiles[domain] = domain_profile
                db.add(domain_profile)
            domain_profile.status = detection["status"]
            domain_profile.reason = detection["reason"]
            domain_profile.profile = behavior["profile"]
            domain_profile.request_count = len(processed_domain_events[domain])
            domain_profile.requests_per_minute = behavior["frequency"]
            domain_profile.sites_detected_on = behavior["sites_detected_on"]
            domain_profile.cookie_usage_count = behavior["cookie_usage"]
            domain_profile.repetition_pattern = behavior["repetition_pattern"]
            domain_profile.anomaly_score = behavior["anomaly_score"]
            domain_profile.last_seen = now

            website_score = website_scores.get(website)
            previous_category = state["category"]
            if website_score is None:
                website_score = WebsiteScore(website=website)
                website_scores[website] = website_score
                db.add(website_score)
            website_score.risk_score = website_risk["risk_score"]
            website_score.category = website_risk["category"]
            website_score.tracker_count = refreshed_metrics["tracker_count"]
            website_score.sensitive_hits = refreshed_metrics["sensitive_hits"]
            website_score.third_party_count = refreshed_metrics["third_party_count"]
            website_score.aggressive_domain_count = refreshed_metrics["aggressive_domains"]
            website_score.request_frequency = refreshed_metrics["request_frequency"]
            website_score.total_requests = refreshed_metrics["total_requests"]
            website_score.last_updated = now
            state["category"] = website_risk["category"]

            for message in analysis["alerts"]:
                db.add(
                    Alert(
                        website=website,
                        domain=domain,
                        message=message,
                        severity=severity_from_risk_level(request_risk["risk_level"]),
                        timestamp=now,
                    )
                )

            if website_risk["category"] == "High Risk" and previous_category != "High Risk":
                db.add(
                    Alert(
                        website=website,
                        domain=domain,
                        message=f"Website {website} is currently High Risk",
                        severity="high",
                        timestamp=now,
                    )
                )

        db.commit()
        print({"requests_reprocessed": len(requests), "websites": len(website_state)})
    finally:
        db.close()


if __name__ == "__main__":
    main()
