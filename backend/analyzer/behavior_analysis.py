"""Behavior profiling for repeated and cross-site tracking."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta
from statistics import mean


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def profile_domain_behavior(*, domain: str, website: str, recent_events: list[dict]) -> dict:
    now = datetime.utcnow()
    one_minute_ago = now - timedelta(minutes=1)

    timestamps = []
    websites = set()
    cookie_events = 0

    for event in recent_events:
        timestamp = _parse_timestamp(event.get("timestamp"))
        if timestamp:
            timestamps.append(timestamp)
        if event.get("website"):
            websites.add(event["website"])
        if event.get("cookies_present"):
            cookie_events += 1

    requests_per_minute = sum(1 for ts in timestamps if ts >= one_minute_ago)
    sites_detected_on = len(websites | ({website} if website else set()))

    repetition_pattern = "sporadic"
    if len(timestamps) >= 3:
        ordered = sorted(timestamps)
        gaps = [
            (ordered[index] - ordered[index - 1]).total_seconds()
            for index in range(1, len(ordered))
        ]
        avg_gap = mean(gaps) if gaps else 0
        if requests_per_minute >= 10:
            repetition_pattern = "burst"
        elif avg_gap and avg_gap <= 20:
            repetition_pattern = "steady"

    if requests_per_minute >= 10 and sites_detected_on >= 3:
        profile = "aggressive cross-site tracker"
    elif sites_detected_on >= 3:
        profile = "cross-site tracking"
    elif requests_per_minute >= 10 or repetition_pattern == "burst":
        profile = "aggressive tracking"
    else:
        profile = "normal"

    website_counter = Counter(event.get("website") for event in recent_events if event.get("website"))
    anomaly_score = min(
        1.0,
        ((requests_per_minute / 15) + (sites_detected_on / 10) + (cookie_events / 20)) / 3,
    )

    return {
        "domain": domain,
        "profile": profile,
        "frequency": requests_per_minute,
        "sites_detected_on": sites_detected_on,
        "cookie_usage": cookie_events,
        "repetition_pattern": repetition_pattern,
        "top_sites": website_counter.most_common(5),
        "anomaly_score": round(anomaly_score, 2),
    }

