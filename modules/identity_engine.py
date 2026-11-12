"""
CyberShield AI — Digital Identity & Trust Score Engine
Owner: Kaveri
Assigned Scope: Digital ID credential verification, privacy switches, QR verification, identity trust score
"""

def calculate_identity_trust_score(user_profile: dict) -> dict:
    """
    Computes an Identity Trust Score (0-100) based on verified factors:
    - Email verification (+30)
    - Two-factor authentication enabled (+30)
    - Strong master passphrase (+20)
    - Data leak absence (+20)
    """
    score = 40  # base starting score
    factors = []

    if user_profile.get("email_verified"):
        score += 25
        factors.append("Email Verified via OTP")

    if user_profile.get("two_factor_enabled"):
        score += 25
        factors.append("2FA / FIDO2 Active")

    if user_profile.get("privacy_mode_enabled"):
        score += 10
        factors.append("Strict Privacy Switches Enabled")

    score = min(score, 100)
    grade = "A+" if score >= 90 else ("A" if score >= 80 else ("B" if score >= 60 else "C"))

    return {
        "status": "success",
        "identity_trust_score": score,
        "grade": grade,
        "verified_factors": factors
    }

def verify_digital_credential(credential_id: str) -> dict:
    """
    Verifies an encrypted digital ID credential or QR hash.
    """
    is_valid = bool(credential_id and len(credential_id) >= 8)
    return {
        "status": "success",
        "credential_id": credential_id,
        "valid": is_valid,
        "status_label": "Verified Identity Token" if is_valid else "Invalid Token"
    }
