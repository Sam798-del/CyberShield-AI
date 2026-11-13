"""
CyberShield AI — Phishing & Domain Spoofing Detection Engine
Owner: Shreya
Assigned Scope: URLs, email content, and raw email headers (spoofing, deceptive domains, malware links)
"""

import re
from urllib.parse import urlparse

HIGH_RISK_TLDS = [".xyz", ".top", ".tk", ".club", ".work", ".gq", ".cf", ".fit", ".rest", ".stream"]
LOOKALIKE_KEYWORDS = ["paypa1", "g00gle", "micros0ft", "app1e", "amaz0n", "sec-login", "verify-account", "auth-check", "secure-bank"]
URGENCY_KEYWORDS = [
    "account suspended", "urgent action required", "verify your account",
    "unauthorized login", "click link below", "update billing",
    "password expired", "immediate verification", "account disabled"
]
FINANCIAL_SOLICITATION_KEYWORDS = [
    "password reset", "gift card", "bank wire", "ssn", "social security",
    "credit card details", "confirm credentials", "billing update"
]

def analyze_phishing(target: str) -> dict:
    """
    Evaluates a URL or email text body for phishing heuristics, homograph lookalikes,
    unencrypted protocols, and social engineering urgency triggers.
    """
    if not target or not target.strip():
        return {
            "status": "error",
            "message": "Target string cannot be empty",
            "risk_score": 0,
            "risk_level": "UNKNOWN"
        }

    t_lower = target.lower().strip()
    flags = []
    score = 0

    # 1. URL & Protocol Analysis
    is_url = t_lower.startswith("http://") or t_lower.startswith("https://") or "www." in t_lower or "." in t_lower

    if is_url:
        if t_lower.startswith("http://"):
            flags.append("Unencrypted connection (HTTP instead of HTTPS)")
            score += 25

        if any(bad_tld in t_lower for bad_tld in HIGH_RISK_TLDS):
            flags.append("High-risk top-level domain (TLD) commonly used in spam/phishing")
            score += 30

        if any(spoof in t_lower for spoof in LOOKALIKE_KEYWORDS):
            flags.append("Lookalike domain / typosquatting detected")
            score += 45

        if "@" in t_lower:
            flags.append("Embedded user credentials / '@' symbol in URL")
            score += 35

        if len(t_lower) > 75:
            flags.append("Excessively long URL path designed to obscure hostname")
            score += 15

        if t_lower.count("-") > 3:
            flags.append("Multiple hyphens in domain name (common in fake phishing portals)")
            score += 20

        # Check for IP address used directly as hostname
        ip_pattern = r'https?://(?:\d{1,3}\.){3}\d{1,3}'
        if re.search(ip_pattern, t_lower):
            flags.append("Direct IP address hostname instead of registered domain")
            score += 40

    # 2. Email Body & Social Engineering Heuristics
    if any(keyword in t_lower for keyword in URGENCY_KEYWORDS):
        flags.append("Urgent call-to-action / social engineering trigger words")
        score += 35

    if any(keyword in t_lower for keyword in FINANCIAL_SOLICITATION_KEYWORDS):
        flags.append("Sensitive credential / financial information solicitation")
        score += 30

    score = min(score, 100)

    # Classify Verdict
    if score >= 75:
        risk_level = "CRITICAL PHISHING THREAT"
        status_color = "danger"
        recommendation = "Do NOT enter credentials or click links. Report email domain immediately."
    elif score >= 45:
        risk_level = "HIGH RISK"
        status_color = "warning"
        recommendation = "Suspicious attributes detected. Verify out-of-band before interacting."
    elif score >= 20:
        risk_level = "MODERATE CAUTION"
        status_color = "warning"
        recommendation = "Minor risks flagged. Proceed with caution."
    else:
        risk_level = "SAFE / LOW RISK"
        status_color = "success"
        recommendation = "URL/content appears safe, but maintain standard security vigilance."
        if not flags:
            flags.append("No obvious phishing indicators detected.")

    return {
        "status": "success",
        "target": target,
        "risk_score": score,
        "risk_level": risk_level,
        "status_color": status_color,
        "flags": flags,
        "recommendation": recommendation
    }
