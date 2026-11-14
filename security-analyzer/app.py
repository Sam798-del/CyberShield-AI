"""
CyberShield AI — Security Analyzer Service
Standalone backend microservice for password analysis and email/domain leak scanning.
This is an independent module; it does NOT import from any other teammate's code.
"""

import os
import re
import math
import time
import hashlib
import sqlite3
import string
import datetime
from datetime import timezone

import requests as http_requests
from flask import Flask, request, jsonify, g
from flask_cors import CORS
# pyrefly: ignore[missing-import]
from flask_limiter import Limiter
# pyrefly: ignore[missing-import]
from flask_limiter.util import get_remote_address

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "analyzer.db")

app = Flask(__name__)
CORS(app)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per hour"],
    storage_uri="memory://",
)

# ---------------------------------------------------------------------------
# Common-passwords list (loaded once at startup)
# ---------------------------------------------------------------------------
COMMON_PASSWORDS_FILE = os.path.join(BASE_DIR, "common_passwords.txt")
COMMON_PASSWORDS: set = set()

if os.path.isfile(COMMON_PASSWORDS_FILE):
    with open(COMMON_PASSWORDS_FILE, "r", encoding="utf-8") as fh:
        for line in fh:
            pw = line.strip()
            if pw:
                COMMON_PASSWORDS.add(pw.lower())

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    """Return a per-request SQLite connection stored on Flask's `g`."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create tables if they don't exist."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scan_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     TEXT,
            scan_type   TEXT    NOT NULL,
            result_summary TEXT NOT NULL,
            score       INTEGER,
            created_at  TEXT    NOT NULL
        )
    """)
    conn.commit()
    conn.close()


init_db()


def _extract_user_id():
    """
    Optionally read a JWT / opaque token from the Authorization header.
    If present, store a hashed version as the user identifier.
    If missing or malformed, return None (anonymous).
    """
    auth = request.headers.get("Authorization", "")
    if not auth:
        return None
    token = auth.removeprefix("Bearer ").strip()
    if not token:
        return None
    return hashlib.sha256(token.encode()).hexdigest()[:16]


def _save_scan(scan_type: str, result_summary: str, score: int | None = None):
    """Persist one scan record (never stores raw password or full email)."""
    uid = _extract_user_id()
    if uid is None:
        return  # anonymous → nothing to save per spec
    db = get_db()
    db.execute(
        "INSERT INTO scan_log (user_id, scan_type, result_summary, score, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (uid, scan_type, result_summary, score, datetime.datetime.now(timezone.utc).isoformat()),
    )
    db.commit()


# ---------------------------------------------------------------------------
# Input-validation helpers
# ---------------------------------------------------------------------------
MAX_PASSWORD_LEN = 1024
MAX_VALUE_LEN = 320  # generous max for email or domain


def _json_error(message: str, status: int = 400):
    return jsonify({"error": message}), status


# ---------------------------------------------------------------------------
# PART A — Password analysis helpers
# ---------------------------------------------------------------------------

# Keyboard sequences for QWERTY layout
KEYBOARD_ROWS = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
]

SEQUENCES = [
    string.ascii_lowercase,       # abcdef...
    string.digits,                # 012345...
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
]

# Common leet-speak substitutions
LEET_MAP = str.maketrans("@013$!7", "aoleset")


def _has_repeated_chars(password: str, min_run: int = 3) -> bool:
    """True if any character repeats ≥ min_run times consecutively."""
    for i in range(len(password) - min_run + 1):
        if len(set(password[i:i + min_run])) == 1:
            return True
    return False


def _has_sequence(password: str, min_run: int = 3) -> bool:
    """True if the password contains ascending/descending runs from SEQUENCES."""
    lower = password.lower()
    for seq in SEQUENCES:
        rev = seq[::-1]
        for start in range(len(seq) - min_run + 1):
            fwd = seq[start:start + min_run]
            bwd = rev[start:start + min_run]
            if fwd in lower or bwd in lower:
                return True
    return False


def _has_keyboard_run(password: str, min_run: int = 4) -> bool:
    """True if the password contains a keyboard-walk run (qwerty, asdf…)."""
    lower = password.lower()
    for row in KEYBOARD_ROWS:
        rev = row[::-1]
        for start in range(len(row) - min_run + 1):
            if row[start:start + min_run] in lower:
                return True
            if rev[start:start + min_run] in lower:
                return True
    return False


def _is_leet_common(password: str) -> bool:
    """True if the password is a leet-speak variant of a common password."""
    decoded = password.lower().translate(LEET_MAP)
    return decoded in COMMON_PASSWORDS


def _calc_entropy(password: str) -> float:
    """Entropy in bits = length × log2(pool_size). Pool from actual char classes."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 32
    if pool == 0:
        return 0.0
    return len(password) * math.log2(pool)


def _crack_time_text(entropy_bits: float) -> str:
    """Human-friendly estimated crack time assuming 10 billion guesses/sec."""
    if entropy_bits <= 0:
        return "instant"
    guesses = 2 ** entropy_bits
    seconds = guesses / 1e10
    if seconds < 1:
        return "less than a second"
    if seconds < 60:
        return f"about {int(seconds)} seconds"
    minutes = seconds / 60
    if minutes < 60:
        return f"about {int(minutes)} minutes"
    hours = minutes / 60
    if hours < 24:
        return f"about {int(hours)} hours"
    days = hours / 24
    if days < 365:
        return f"about {int(days)} days"
    years = days / 365
    if years < 1e6:
        return f"about {int(years)} years"
    return f"about {years:.1e} years"


def _check_hibp_password(password: str) -> tuple[bool, int]:
    """
    Query Have I Been Pwned Pwned-Passwords via k-anonymity.
    Returns (breached: bool, count: int).
    Only the first 5 hex chars of the SHA-1 hash are sent; the full password
    and full hash never leave this server.
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    try:
        resp = http_requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=5,
            headers={"User-Agent": "CyberShield-AI-SecurityAnalyzer"},
        )
        resp.raise_for_status()
    except Exception:
        # Network/API failure → report unknown, don't crash
        return False, 0

    for line in resp.text.splitlines():
        parts = line.strip().split(":")
        if len(parts) == 2 and parts[0] == suffix:
            return True, int(parts[1])
    return False, 0


def analyze_password(password: str) -> dict:
    """Run every check and return the full result dict."""
    issues: list[str] = []
    tips: list[str] = []
    penalty = 0.0

    # 1. Length
    length = len(password)
    if length < 8:
        issues.append("Password is shorter than 8 characters")
        tips.append("Use at least 12 characters for a strong password")
        penalty += 25
    elif length < 12:
        tips.append("Consider extending to 12+ characters for extra strength")
        penalty += 10

    # 2. Character variety
    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"[0-9]", password))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))
    variety = sum([has_upper, has_lower, has_digit, has_symbol])
    if variety < 2:
        issues.append("Very low character variety (only 1 character class)")
        tips.append("Mix uppercase, lowercase, numbers, and symbols")
        penalty += 20
    elif variety < 3:
        issues.append("Limited character variety (only 2 character classes)")
        tips.append("Add at least one more character class (symbols recommended)")
        penalty += 10
    elif variety < 4:
        tips.append("Adding symbols would further improve strength")

    # 3. Common password
    is_common = password.lower() in COMMON_PASSWORDS
    force_weak = False
    if is_common:
        issues.append("This password is on the list of most commonly used passwords")
        tips.append("Avoid any password that appears on common-password lists")
        force_weak = True
        penalty += 40

    # 4a. Repeated characters
    if _has_repeated_chars(password):
        issues.append("Contains repeated characters (e.g. aaa, 111)")
        tips.append("Avoid repeating the same character multiple times in a row")
        penalty += 10

    # 4b. Sequential characters
    if _has_sequence(password):
        issues.append("Contains sequential characters (e.g. 1234, abcd)")
        tips.append("Avoid alphabetical or numerical sequences")
        penalty += 10

    # 4c. Keyboard runs
    if _has_keyboard_run(password):
        issues.append("Contains a keyboard pattern (e.g. qwerty, asdf)")
        tips.append("Avoid keyboard-walk patterns")
        penalty += 10

    # 4d. Leet-speak of common password
    if not is_common and _is_leet_common(password):
        issues.append("This is a common password with obvious substitutions (e.g. p@ssw0rd)")
        tips.append("Leet-speak substitutions do not make a common password secure")
        force_weak = True
        penalty += 35

    # 5. Entropy
    raw_entropy = _calc_entropy(password)
    adjusted_entropy = max(0.0, raw_entropy - penalty)

    # 6. Breach check
    breached, breach_count = _check_hibp_password(password)
    if breached:
        issues.append(f"This password has appeared in {breach_count:,} known data breaches")
        tips.append("Change this password immediately wherever it is used")
        force_weak = True

    # Score (0-100)
    score = int(min(100, max(0, adjusted_entropy * 100 / 80)))
    if force_weak:
        score = min(score, 15)

    # Label
    if force_weak or score < 40:
        label = "weak"
    elif score < 70:
        label = "medium"
    else:
        label = "strong"

    if not tips:
        tips.append("Your password looks strong — keep it up!")

    return {
        "score": score,
        "label": label,
        "entropy_bits": round(adjusted_entropy, 2),
        "breached": breached,
        "breach_count": breach_count,
        "issues": issues,
        "tips": tips,
        "estimated_crack_time": _crack_time_text(adjusted_entropy),
    }


# ---------------------------------------------------------------------------
# PART B — Email / Domain leak-scan helpers  (XposedOrNot — free, no key)
# ---------------------------------------------------------------------------

EMAIL_RE = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
DOMAIN_RE = re.compile(r"^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$")

XON_CHECK_URL = "https://api.xposedornot.com/v1/check-email/{email}"
XON_ANALYTICS_URL = "https://api.xposedornot.com/v1/breach-analytics"
XON_BREACHES_URL = "https://api.xposedornot.com/v1/breaches"

# Simple in-memory cache: key → (result_dict, expiry_timestamp)
# TTL keeps us well under the free-tier ~2 req/s, ~100/day cap
_leak_cache: dict[str, tuple[dict, float]] = {}
CACHE_TTL = 300  # 5 minutes


def _cache_get(key: str) -> dict | None:
    entry = _leak_cache.get(key)
    if entry and entry[1] > time.time():
        return entry[0]
    _leak_cache.pop(key, None)
    return None


def _cache_set(key: str, value: dict):
    _leak_cache[key] = (value, time.time() + CACHE_TTL)


def _mask_email(email: str) -> str:
    """Mask an email for storage: n***a@gmail.com"""
    local, domain = email.rsplit("@", 1)
    if len(local) <= 2:
        masked = local[0] + "***"
    else:
        masked = local[0] + "***" + local[-1]
    return f"{masked}@{domain}"


def _hash_email(email: str) -> str:
    return hashlib.sha256(email.lower().strip().encode()).hexdigest()[:16]


def _now_iso() -> str:
    return datetime.datetime.now(timezone.utc).isoformat()


def _api_error(message: str) -> dict:
    return {
        "found": False,
        "breach_count": 0,
        "breaches": [],
        "advice": message,
        "source": "XposedOrNot",
        "checked_at": _now_iso(),
        "error": message,
    }


def _query_xon_email(email: str) -> dict:
    """
    Query XposedOrNot free API for an email address.
    Step 1: /v1/check-email/{email}  → quick yes/no
    Step 2: /v1/breach-analytics?email={email} → detailed breach list
    """
    cache_key = f"email:{email.lower()}"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    headers = {"User-Agent": "CyberShield-AI-SecurityAnalyzer"}

    # --- Step 1: quick check (with 1 automatic retry on 429 rate limit) ---
    resp = None
    for attempt in range(2):
        try:
            resp = http_requests.get(
                XON_CHECK_URL.format(email=email),
                headers=headers,
                timeout=10,
            )
            if resp.status_code == 429 and attempt == 0:
                time.sleep(1.2)
                continue
            break
        except http_requests.Timeout:
            return _api_error("XposedOrNot API timed out. Please try again later.")
        except http_requests.ConnectionError:
            return _api_error("Could not reach XposedOrNot API. Check your internet connection.")
        except http_requests.RequestException as exc:
            return _api_error(f"External API error: {exc}")

    if resp is None:
        return _api_error("Failed to connect to breach database.")
    if resp.status_code == 429:
        return _api_error("Rate limit reached on XposedOrNot. Please wait 10 seconds and try again.")
    if resp.status_code == 404:
        result = {
            "found": False,
            "breach_count": 0,
            "breaches": [],
            "advice": "No known breaches found in XposedOrNot.",
            "source": "XposedOrNot",
            "checked_at": _now_iso(),
        }
        _cache_set(cache_key, result)
        return result
    if resp.status_code != 200:
        return _api_error(f"XposedOrNot returned HTTP {resp.status_code}.")

    # The check-email endpoint returns:
    #   {"breaches": [["BreachA","BreachB",...]]}  when breaches exist
    #   {"Error": "Not found", "email": null}       when email is clean (HTTP 200!)
    try:
        check_data = resp.json()
    except Exception:
        return _api_error("Invalid response from XposedOrNot API.")

    # Detect "Not found" body early — XposedOrNot uses HTTP 200 even for clean emails
    if isinstance(check_data, dict) and (
        check_data.get("Error") == "Not found"
        or check_data.get("error") == "Not found"
    ):
        result = {
            "found": False,
            "breach_count": 0,
            "breaches": [],
            "advice": "No known breaches found in XposedOrNot.",
            "source": "XposedOrNot",
            "checked_at": _now_iso(),
        }
        _cache_set(cache_key, result)
        return result

    # Extract breach names from the check response
    breach_names = []
    if isinstance(check_data, dict):
        raw_breaches = check_data.get("breaches") or check_data.get("Breaches_Details") or []
        if isinstance(raw_breaches, list):
            for item in raw_breaches:
                if isinstance(item, str):
                    breach_names.append(item)
                elif isinstance(item, list):
                    breach_names.extend(item)

    # If still no breach names were extracted, treat as clean
    if not breach_names:
        result = {
            "found": False,
            "breach_count": 0,
            "breaches": [],
            "advice": "No known breaches found in XposedOrNot.",
            "source": "XposedOrNot",
            "checked_at": _now_iso(),
        }
        _cache_set(cache_key, result)
        return result

    # --- Step 2: get detailed analytics ---
    breaches = []
    try:
        time.sleep(0.6)  # respect ~2 req/s rate limit
        analytics_resp = http_requests.get(
            XON_ANALYTICS_URL,
            params={"email": email},
            headers=headers,
            timeout=10,
        )
        if analytics_resp.status_code == 200:
            analytics = analytics_resp.json()
            # The analytics endpoint nests data under "ExposedBreaches" → "breaches_details"
            exposed = analytics.get("ExposedBreaches") or analytics.get("exposedBreaches") or {}
            details_list = exposed.get("breaches_details") or exposed.get("Breaches_Details") or []
            if isinstance(details_list, list):
                for b in details_list:
                    if isinstance(b, dict):
                        # Normalize various key name styles from the API
                        name = (b.get("breach") or b.get("Breach")
                                or b.get("name") or b.get("Name") or "Unknown")
                        date = (b.get("xposed_date") or b.get("breachDate")
                                or b.get("BreachDate") or b.get("date") or "Unknown")
                        data_raw = (b.get("exposedData") or b.get("xposed_data")
                                    or b.get("DataClasses") or b.get("data_exposed")
                                    or b.get("dataclasses") or "")
                        if isinstance(data_raw, str):
                            # Handle both comma and semicolon separated data strings
                            delim = ";" if ";" in data_raw else ","
                            data_exposed = [d.strip() for d in data_raw.split(delim) if d.strip()]
                        elif isinstance(data_raw, list):
                            data_exposed = []
                            for item in data_raw:
                                if isinstance(item, str) and ";" in item:
                                    data_exposed.extend([d.strip() for d in item.split(";") if d.strip()])
                                else:
                                    data_exposed.append(str(item).strip())
                        else:
                            data_exposed = []
                        breaches.append({
                            "name": (b.get("breachID") or b.get("breach") or b.get("Breach")
                                     or b.get("name") or b.get("Name") or "Unknown"),
                            "date": (b.get("breachedDate") or b.get("xposed_date")
                                     or b.get("breachDate") or b.get("BreachDate")
                                     or b.get("date") or "Unknown"),
                            "data_exposed": data_exposed,
                        })
    except Exception:
        pass  # analytics is best-effort; we still have the breach names

    # If analytics didn't yield details, fall back to just names from step 1
    if not breaches and breach_names:
        breaches = [{"name": n, "date": "Unknown", "data_exposed": []} for n in breach_names]

    breach_count = len(breaches) if breaches else len(breach_names)

    result = {
        "found": breach_count > 0,
        "breach_count": breach_count,
        "breaches": breaches,
        "advice": (
            "Your email was found in known breaches. Change passwords on the affected services and enable 2FA."
            if breach_count > 0
            else "No known breaches found in XposedOrNot."
        ),
        "source": "XposedOrNot",
        "checked_at": _now_iso(),
    }
    _cache_set(cache_key, result)
    return result


def _query_xon_domain(domain: str) -> dict:
    """
    Query XposedOrNot /v1/breaches and filter by the requested domain.
    The breaches endpoint is public and requires no API key.
    """
    cache_key = f"domain:{domain.lower()}"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    headers = {"User-Agent": "CyberShield-AI-SecurityAnalyzer"}
    try:
        resp = http_requests.get(
            XON_BREACHES_URL,
            headers=headers,
            timeout=15,
        )
    except http_requests.Timeout:
        return _api_error("XposedOrNot API timed out. Please try again later.")
    except http_requests.ConnectionError:
        return _api_error("Could not reach XposedOrNot API. Check your internet connection.")
    except http_requests.RequestException as exc:
        return _api_error(f"External API error: {exc}")

    if resp.status_code == 429:
        return _api_error("Rate limit reached on XposedOrNot. Please try again later.")
    if resp.status_code != 200:
        return _api_error(f"XposedOrNot returned HTTP {resp.status_code}.")

    try:
        raw = resp.json()
    except Exception:
        return _api_error("Invalid response from XposedOrNot API.")

    # raw is a list of breach objects; filter by domain
    domain_lower = domain.lower().strip()
    root_domain = domain_lower[4:] if domain_lower.startswith("www.") else domain_lower
    # Extract base brand name (e.g. 'adobe' from 'adobe.com')
    brand_name = root_domain.split(".")[0] if "." in root_domain else root_domain
    matched = []

    # The API may return a list or a dict with a key holding the list
    breach_list = raw if isinstance(raw, list) else raw.get("exposedBreaches", raw.get("breaches", []))

    for b in (breach_list if isinstance(breach_list, list) else []):
        if not isinstance(b, dict):
            continue
        b_domain = (b.get("domain") or b.get("Domain") or "").lower().strip()
        b_name = (b.get("breachID") or b.get("breach") or b.get("name") or b.get("Name") or "").lower().strip()
        
        # Robust match against full domain, root domain, or brand name
        is_match = (
            root_domain == b_domain
            or root_domain in b_domain
            or (b_domain and b_domain in root_domain)
            or (brand_name and len(brand_name) >= 3 and (brand_name == b_name or b_name.startswith(brand_name)))
        )
        if is_match:
            data_raw = (b.get("exposedData") or b.get("xposed_data")
                        or b.get("DataClasses") or b.get("data_exposed")
                        or b.get("dataclasses") or "")
            if isinstance(data_raw, str):
                delim = ";" if ";" in data_raw else ","
                data_exposed = [d.strip() for d in data_raw.split(delim) if d.strip()]
            elif isinstance(data_raw, list):
                data_exposed = []
                for item in data_raw:
                    if isinstance(item, str) and ";" in item:
                        data_exposed.extend([d.strip() for d in item.split(";") if d.strip()])
                    else:
                        data_exposed.append(str(item).strip())
            else:
                data_exposed = []
            matched.append({
                "name": (b.get("breachID") or b.get("breach") or b.get("name")
                         or b.get("Name") or "Unknown"),
                "date": (b.get("breachedDate") or b.get("xposed_date")
                         or b.get("breachDate") or b.get("BreachDate")
                         or b.get("date") or "Unknown"),
                "data_exposed": data_exposed,
            })

    result = {
        "found": len(matched) > 0,
        "breach_count": len(matched),
        "breaches": matched,
        "advice": (
            f"Domain {domain} is linked to known breaches. Review affected accounts and rotate credentials."
            if matched
            else f"No known breaches found in XposedOrNot for domain {domain}."
        ),
        "source": "XposedOrNot",
        "checked_at": _now_iso(),
    }
    _cache_set(cache_key, result)
    return result


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/api/analyzer/password", methods=["POST"])
@limiter.limit("30 per minute")
def password_endpoint():
    """PART A: Password strength analysis."""
    body = request.get_json(silent=True)
    if body is None:
        return _json_error("Request body must be valid JSON with Content-Type application/json")

    password = body.get("password")
    if password is None or not isinstance(password, str):
        return _json_error("Field 'password' (string) is required")
    if len(password) == 0:
        return _json_error("Password must not be empty")
    if len(password) > MAX_PASSWORD_LEN:
        return _json_error(f"Password exceeds maximum length of {MAX_PASSWORD_LEN} characters", 413)

    result = analyze_password(password)

    # Save record — NEVER store the actual password
    _save_scan(
        scan_type="password",
        result_summary=result["label"],
        score=result["score"],
    )

    return jsonify(result), 200


@app.route("/api/analyzer/leak", methods=["POST"])
@limiter.limit("15 per minute")
def leak_endpoint():
    """PART B: Email / domain leak scanner."""
    body = request.get_json(silent=True)
    if body is None:
        return _json_error("Request body must be valid JSON with Content-Type application/json")

    leak_type = body.get("type")
    value = body.get("value")

    if leak_type not in ("email", "domain"):
        return _json_error("Field 'type' must be 'email' or 'domain'")
    if value is None or not isinstance(value, str) or len(value.strip()) == 0:
        return _json_error("Field 'value' (non-empty string) is required")

    value = value.strip()
    if len(value) > MAX_VALUE_LEN:
        return _json_error(f"Value exceeds maximum length of {MAX_VALUE_LEN} characters", 413)

    if leak_type == "email":
        if not EMAIL_RE.match(value):
            return _json_error("Invalid email format")
        result = _query_xon_email(value)
        # Save with masked/hashed email — never the full address
        _save_scan(
            scan_type="leak_email",
            result_summary=f"found={result['found']},count={result['breach_count']},masked={_mask_email(value)}",
            score=result["breach_count"],
        )
    else:
        if not DOMAIN_RE.match(value):
            return _json_error("Invalid domain format")
        result = _query_xon_domain(value)
        _save_scan(
            scan_type="leak_domain",
            result_summary=f"found={result['found']},count={result['breach_count']},domain={value}",
            score=result["breach_count"],
        )

    return jsonify(result), 200


@app.route("/api/analyzer/health", methods=["GET"])
def health():
    return jsonify({
        "status": "online",
        "service": "Security Analyzer",
        "project": "CyberShield AI",
    })


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.errorhandler(404)
def not_found(_e):
    return _json_error("Endpoint not found", 404)


@app.errorhandler(405)
def method_not_allowed(_e):
    return _json_error("Method not allowed", 405)


@app.errorhandler(429)
def rate_limit_exceeded(_e):
    return jsonify({"error": "Rate limit exceeded. Please slow down."}), 429


@app.errorhandler(500)
def server_error(_e):
    return _json_error("Internal server error", 500)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("ANALYZER_PORT", 5050))
    print("=" * 60)
    print("  CyberShield AI — Security Analyzer Service")
    print("=" * 60)
    print(f"  POST  http://localhost:{port}/api/analyzer/password")
    print(f"  POST  http://localhost:{port}/api/analyzer/leak")
    print(f"  GET   http://localhost:{port}/api/analyzer/health")
    print("=" * 60)
    app.run(host="0.0.0.0", port=port, debug=True)
