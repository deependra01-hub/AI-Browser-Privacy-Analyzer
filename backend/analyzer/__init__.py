"""Analysis engine orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .behavior_analysis import profile_domain_behavior
from .risk_scoring import build_alerts, calculate_request_risk, calculate_website_risk
from .tracker_detection import analyze_domain_request


@dataclass
class LocalIntelligenceEngine:
    """Coordinates tracker detection, behavior profiling, and risk scoring."""

    def analyze_request(
        self,
        *,
        request_url: str,
        domain: str,
        website: str,
        method: str,
        cookies: str | None,
        recent_domain_events: Iterable[dict],
        website_metrics: dict,
    ) -> dict:
        detection = analyze_domain_request(
            request_url=request_url,
            domain=domain,
            website=website,
            cookies=cookies,
            recent_request_count=website_metrics.get("recent_domain_request_count", 0),
        )
        behavior = profile_domain_behavior(
            domain=domain,
            website=website,
            recent_events=list(recent_domain_events),
        )
        request_risk = calculate_request_risk(
            tracker_status=detection["status"],
            behavior_profile=behavior["profile"],
            sensitive_hits=len(detection["material_data"]),
            third_party=detection["third_party"],
        )
        alerts = build_alerts(
            domain=domain,
            detection=detection,
            behavior=behavior,
            request_risk=request_risk,
        )
        website_risk = calculate_website_risk(
            trackers=website_metrics.get("tracker_count", 0),
            sensitive_hits=website_metrics.get("sensitive_hits", 0),
            request_frequency=website_metrics.get("request_frequency", 0),
            third_party=website_metrics.get("third_party_count", 0),
            aggressive_domains=website_metrics.get("aggressive_domains", 0),
        )
        return {
            "detection": detection,
            "behavior": behavior,
            "request_risk": request_risk,
            "website_risk": website_risk,
            "alerts": alerts,
        }
