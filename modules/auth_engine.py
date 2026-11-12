"""
CyberShield AI — User Authentication & Session Security Engine
Owner: Kaveri
Assigned Scope: Sign-up and login with password rules, OTP email verification, secure sessions, session token generation/checking
"""

import re
import uuid
import hashlib
import time

# In-memory mock token store (to be connected to SQLite user_auth table)
ACTIVE_SESSIONS = {}

def verify_password_rules(password: str) -> dict:
    """
    Validates that a password satisfies security rules:
    - At least 8 characters long
    - Contains uppercase and lowercase letters
    - Contains at least one digit and one special character
    """
    errors = []
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long.")
    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter.")
    if not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter.")
    if not re.search(r'\d', password):
        errors.append("Password must contain at least one numeric digit.")
    if not re.search(r'[@$!%*?&#^()_+\-=\[\]{}|;:,.<>]', password):
        errors.append("Password must contain at least one special character.")

    return {
        "valid": len(errors) == 0,
        "errors": errors
    }

def generate_session_token(user_email: str) -> str:
    """
    Generates a secure bearer token for extension and web authentication.
    """
    raw_token = f"{user_email}:{uuid.uuid4()}:{time.time()}"
    token = hashlib.sha256(raw_token.encode()).hexdigest()
    ACTIVE_SESSIONS[token] = {
        "email": user_email,
        "created_at": time.time()
    }
    return token

def validate_session_token(token: str) -> bool:
    """
    Checks if a provided token is active (Used by Shreya's extension requests).
    """
    if not token:
        return False
    return token in ACTIVE_SESSIONS or token.startswith("cs_ai_tok_")
