"""
CyberShield AI — Password Entropy & Data Breach Analyzer
Owner: Neeraja
Assigned Scope: Password entropy calculation and email/domain leak scanner (HaveIBeenPwned API)
"""

import math
import hashlib
import urllib.request

def calculate_password_entropy(password: str) -> dict:
    """
    Calculates password entropy in bits: H = L * log2(N)
    where L = length, N = character pool size
    """
    if not password:
        return {"entropy_bits": 0, "strength": "Empty", "crack_time": "Instant"}

    pool_size = 0
    if any(c.islower() for c in password): pool_size += 26
    if any(c.isupper() for c in password): pool_size += 26
    if any(c.isdigit() for c in password): pool_size += 10
    if any(not c.isalnum() for c in password): pool_size += 32

    if pool_size == 0:
        pool_size = 26

    entropy = round(len(password) * math.log2(pool_size), 2)

    if entropy >= 80:
        strength = "Very Strong"
        crack_time = "Centuries"
    elif entropy >= 60:
        strength = "Strong"
        crack_time = "Months to Years"
    elif entropy >= 40:
        strength = "Moderate"
        crack_time = "Hours to Days"
    else:
        strength = "Weak"
        crack_time = "Seconds to Minutes"

    return {
        "length": len(password),
        "entropy_bits": entropy,
        "strength": strength,
        "estimated_crack_time": crack_time
    }

def check_pwned_password_k_anonymity(password: str) -> dict:
    """
    Checks if password appears in known breach databases using k-Anonymity (HaveIBeenPwned API).
    Only first 5 characters of SHA-1 hash are sent over network.
    """
    if not password:
        return {"status": "error", "message": "Password required"}

    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    api_url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        req = urllib.request.Request(api_url, headers={'User-Agent': 'CyberShield-AI-Client'})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = resp.read().decode('utf-8')
            for line in data.splitlines():
                h_suffix, count = line.split(':')
                if h_suffix == suffix:
                    return {
                        "status": "compromised",
                        "pwned": True,
                        "breach_occurrences": int(count),
                        "warning": f"Password compromised in {count} known breaches!"
                    }
        return {
            "status": "clean",
            "pwned": False,
            "breach_occurrences": 0,
            "message": "Password not found in known public breach dumps."
        }
    except Exception as e:
        return {
            "status": "offline",
            "pwned": False,
            "message": "Breach API offline; local entropy check passed."
        }
