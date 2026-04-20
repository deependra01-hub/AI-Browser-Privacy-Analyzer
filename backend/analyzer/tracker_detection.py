"""Tracker and sensitive data detection helpers."""

from __future__ import annotations

import re
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urlparse

KNOWN_TRACKER_PATTERNS = {
    "doubleclick.net",
    "googletagmanager.com",
    "google-analytics.com",
    "facebook.net",
    "connect.facebook.net",
    "hotjar.com",
    "mixpanel.com",
    "segment.com",
    "amplitude.com",
    "adsrvr.org",
    "taboola.com",
    "outbrain.com",
    "branch.io",
    "criteo.com",
}

TRACKING_KEYWORDS = {
    "ad",
    "ads",
    "analytics",
    "track",
    "tracking",
    "pixel",
    "beacon",
    "collect",
    "telemetry",
    "metrics",
    "fingerprint",
}

PERSONAL_KEYS = {"email", "phone", "mobile", "dob", "ssn", "user_id"}
AUTH_KEYS = {"token", "auth", "session"}
PASSWORD_KEYS = {"password", "passwd"}
LOCATION_KEYS = {"location", "lat", "lon", "gps"}
PAYMENT_KEYS = {"credit", "card"}
ALL_TRACKED_KEYS = PERSONAL_KEYS | AUTH_KEYS | PASSWORD_KEYS | LOCATION_KEYS | PAYMENT_KEYS

SENSITIVE_LABELS = {
    "email": "Email address",
    "token": "Auth token",
    "session": "Session token",
    "auth": "Authentication token",
    "password": "Password field",
    "passwd": "Password field",
    "phone": "Phone number",
    "mobile": "Phone number",
    "dob": "Date of birth",
    "ssn": "Government identifier",
    "user_id": "User identifier",
    "location": "Location data",
    "lat": "Latitude",
    "lon": "Longitude",
    "gps": "GPS data",
    "credit": "Payment data",
    "card": "Card data",
    "sensitive-path": "Sensitive page path",
}

MATERIAL_RISK_KEYS = PERSONAL_KEYS | PASSWORD_KEYS | LOCATION_KEYS | PAYMENT_KEYS


def normalize_domain(value: str | None) -> str:
    if not value:
        return ""
    parsed = urlparse(value if "://" in value else f"https://{value}")
    domain = (parsed.netloc or parsed.path).lower().strip()
    if domain.startswith("www."):
        domain = domain[4:]
    return domain.split("/")[0]


def root_domain(value: str | None) -> str:
    domain = normalize_domain(value)
    parts = [part for part in domain.split(".") if part]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def is_third_party(domain: str, website: str) -> bool:
    return bool(domain and website and root_domain(domain) != root_domain(website))


def normalize_key_name(value: str) -> str:
    cleaned = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
    return re.sub(r"_+", "_", cleaned)


def detect_indicator_key(raw_key: str) -> str | None:
    normalized = normalize_key_name(raw_key)
    if not normalized:
        return None
    tokens = [token for token in normalized.split("_") if token]
    token_set = set(tokens)

    if normalized in ALL_TRACKED_KEYS:
        return normalized
    if {"user", "id"}.issubset(token_set) or "userid" in token_set:
        return "user_id"

    for key in sorted(ALL_TRACKED_KEYS, key=len, reverse=True):
        key_tokens = set(key.split("_"))
        if key_tokens.issubset(token_set):
            return key
    return None


def parse_cookie_names(cookie_header: str) -> list[str]:
    cookie = SimpleCookie()
    try:
        cookie.load(cookie_header)
        if cookie:
            return list(cookie.keys())
    except Exception:
        pass

    names = []
    for item in cookie_header.split(";"):
        if "=" in item:
            names.append(item.split("=", 1)[0].strip())
    return names


def extract_sensitive_indicators(request_url: str, cookies: str | None) -> list[str]:
    indicators: set[str] = set()
    parsed = urlparse(request_url)
    for key in parse_qs(parsed.query, keep_blank_values=True).keys():
        marker = detect_indicator_key(key)
        if marker:
            indicators.add(f"query:{marker}")

    if cookies:
        for cookie_name in parse_cookie_names(cookies):
            marker = detect_indicator_key(cookie_name)
            if marker:
                indicators.add(f"cookie:{marker}")

    path = parsed.path.lower()
    if "login" in path or "checkout" in path:
        indicators.add("context:sensitive-path")

    return sorted(indicators)


def parse_indicator(indicator: str) -> tuple[str, str]:
    if ":" in indicator:
        prefix, marker = indicator.split(":", 1)
        return prefix, marker
    return "raw", indicator


def classify_data_exposure(indicators: list[str], cookies_present: bool) -> dict:
    labels: set[str] = set()
    material_markers: set[str] = set()
    auth_markers: set[str] = set()

    for indicator in indicators:
        _, marker = parse_indicator(indicator)
        label = SENSITIVE_LABELS.get(marker)
        if label:
            labels.add(label)
        if marker in MATERIAL_RISK_KEYS:
            material_markers.add(marker)
        if marker in AUTH_KEYS:
            auth_markers.add(marker)

    if cookies_present:
        labels.add("Cookies")

    return {
        "labels": sorted(labels),
        "material_markers": sorted(material_markers),
        "auth_markers": sorted(auth_markers),
    }


def summarize_sensitive_data(indicators: list[str], cookies_present: bool) -> list[str]:
    return classify_data_exposure(indicators, cookies_present)["labels"]


def keyword_hits(domain: str) -> list[str]:
    lowered = domain.lower()
    tokens = [token for token in re.split(r"[^a-z0-9]+", lowered) if token]
    hits = []
    for keyword in TRACKING_KEYWORDS:
        if len(keyword) <= 3:
            if keyword in tokens:
                hits.append(keyword)
        elif any(keyword in token for token in tokens):
            hits.append(keyword)
    return sorted(set(hits))


def is_known_tracker(domain: str) -> bool:
    lowered = domain.lower()
    return any(pattern in lowered for pattern in KNOWN_TRACKER_PATTERNS)


def analyze_domain_request(
    *,
    request_url: str,
    domain: str,
    website: str,
    cookies: str | None,
    recent_request_count: int,
) -> dict:
    normalized_domain = normalize_domain(domain)
    third_party = is_third_party(normalized_domain, website)
    hits = keyword_hits(normalized_domain)
    sensitive_indicators = extract_sensitive_indicators(request_url, cookies)
    exposure = classify_data_exposure(sensitive_indicators, bool(cookies))
    reasons: list[str] = []

    if is_known_tracker(normalized_domain):
        status = "known tracker"
        reasons.append("matches known tracker list")
    else:
        suspicion_score = 0
        if hits:
            suspicion_score += 1
            reasons.append(f"tracking keyword(s): {', '.join(hits)}")
        if recent_request_count >= 8:
            suspicion_score += 1
            reasons.append("high request frequency")
        if third_party:
            suspicion_score += 1
            reasons.append("third-party domain")
        if exposure["material_markers"] and third_party:
            suspicion_score += 1
            reasons.append("potentially sensitive data sent to third-party")
        elif exposure["auth_markers"] and third_party and hits:
            suspicion_score += 1
            reasons.append("token-like metadata sent to tracking endpoint")

        status = "suspicious" if suspicion_score >= 2 else "safe"
        if not reasons:
            reasons.append("no strong tracking indicators")

    return {
        "domain": normalized_domain,
        "status": status,
        "reason": " + ".join(reasons),
        "third_party": third_party,
        "keyword_hits": hits,
        "sensitive_indicators": sensitive_indicators,
        "material_data": exposure["material_markers"],
        "auth_data": exposure["auth_markers"],
        "shared_data_labels": exposure["labels"],
    }
