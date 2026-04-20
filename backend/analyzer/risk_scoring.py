"""Risk scoring and alert generation."""

from __future__ import annotations


def risk_category(score: int) -> str:
    if score >= 75:
        return "High Risk"
    if score >= 40:
        return "Medium Risk"
    return "Low Risk"


def calculate_request_risk(
    *,
    tracker_status: str,
    behavior_profile: str,
    sensitive_hits: int,
    third_party: bool,
) -> dict:
    score = 0
    if tracker_status == "known tracker":
        score += 28
    elif tracker_status == "suspicious":
        score += 16

    if "aggressive" in behavior_profile:
        score += 18
    elif "cross-site" in behavior_profile:
        score += 12

    if third_party:
        score += 8

    score += min(28, sensitive_hits * 10)
    score = min(100, score)

    if score >= 70:
        risk_level = "high"
    elif score >= 40:
        risk_level = "medium"
    else:
        risk_level = "low"

    return {"score": score, "risk_level": risk_level}


def calculate_website_risk(
    *,
    trackers: int,
    sensitive_hits: int,
    request_frequency: int,
    third_party: int,
    aggressive_domains: int,
) -> dict:
    tracker_component = min(34, trackers * 9)
    sensitive_component = min(26, sensitive_hits * 9)
    frequency_component = min(12, max(0, request_frequency - 3))
    third_party_component = min(16, third_party * 4)
    aggressive_component = min(18, aggressive_domains * 6)
    score = min(100, tracker_component + sensitive_component + frequency_component + third_party_component + aggressive_component)
    return {"risk_score": score, "category": risk_category(score)}


def build_alerts(*, domain: str, detection: dict, behavior: dict, request_risk: dict) -> list[str]:
    alerts: list[str] = []
    if detection["status"] == "known tracker":
        alerts.append("High-risk tracker detected on this website")
    if "aggressive" in behavior["profile"]:
        alerts.append(f"Aggressive tracking behavior observed from {domain}")
    if "cross-site" in behavior["profile"]:
        alerts.append(f"Cross-site tracking activity detected from {domain}")
    if detection.get("material_data") and detection.get("third_party"):
        alerts.append("Sensitive pattern found in request metadata")
    if request_risk["risk_level"] == "high" and not alerts:
        alerts.append(f"High-risk request detected for {domain}")
    return alerts


def derive_request_risk_types(*, detection: dict, behavior: dict, cookies_present: bool) -> list[str]:
    risk_types: list[str] = []

    if detection["status"] == "known tracker":
        risk_types.append("Known tracker contact")
    elif detection["status"] == "suspicious":
        risk_types.append("Suspicious tracking endpoint")

    if detection["third_party"]:
        risk_types.append("Third-party data transfer")

    if "cross-site" in behavior["profile"]:
        risk_types.append("Cross-site tracking")

    if "aggressive" in behavior["profile"]:
        risk_types.append("Aggressive tracking")

    indicators = set(detection.get("sensitive_indicators", []))
    if any(token in indicator for indicator in indicators for token in ["password", "passwd"]):
        risk_types.append("Credential sharing")
    if detection["third_party"] and any(token in indicator for indicator in indicators for token in ["token", "auth"]):
        risk_types.append("Credential or session exposure")
    if any(token in indicator for indicator in indicators for token in ["email", "phone", "mobile", "user_id", "ssn", "dob"]):
        risk_types.append("Personal identifier sharing")
    if any(token in indicator for indicator in indicators for token in ["location", "lat", "lon", "gps"]):
        risk_types.append("Location sharing")
    if any(token in indicator for indicator in indicators for token in ["credit", "card"]):
        risk_types.append("Payment data exposure")
    if cookies_present and detection["third_party"] and detection["status"] != "safe":
        risk_types.append("Cookie-based tracking")

    if not risk_types and detection["status"] == "safe":
        risk_types.append("Low observable privacy risk")

    return risk_types
