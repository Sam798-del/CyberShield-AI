"""Everything security-related for sign-up, login, OTP and sessions."""
import hashlib
import hmac
import re
import secrets
import smtplib
import ssl
import time
from collections import defaultdict, deque
from email.message import EmailMessage
from functools import wraps

import jwt
from flask import current_app, g, request
from werkzeug.security import check_password_hash, generate_password_hash

from db import get_db
from responses import ApiError

COOKIE_NAME = "cs_session"
TOKEN_ISSUER = "cybershield-ai"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def now():
    return int(time.time())


# ---------------------------------------------------------------- input checks
def normalize_email(raw):
    email = (raw or "").strip().lower() if isinstance(raw, str) else ""
    pattern = r"[a-z0-9._%+\-]+@[a-z0-9\-]+(\.[a-z0-9\-]+)*\.[a-z]{2,}"
    if len(email) > 254 or not re.fullmatch(pattern, email):
        msg = "Enter a valid email address."
        raise ApiError("INVALID_EMAIL", msg, 422, {"email": msg})
    return email


def clean_name(raw):
    name = re.sub(r"\s+", " ", raw).strip() if isinstance(raw, str) else ""
    if not 2 <= len(name) <= 60 or re.search(r"[<>{}\\/\x00-\x1f]", name):
        msg = "Enter your name (2-60 characters, no special symbols)."
        raise ApiError("INVALID_NAME", msg, 422, {"name": msg})
    return name


def clean_phone(raw):
    if raw in (None, ""):
        return None
    phone = re.sub(r"[\s\-()]", "", raw) if isinstance(raw, str) else ""
    if not re.fullmatch(r"\+?\d{7,15}", phone):
        msg = "Enter a valid phone number (7-15 digits, optional +)."
        raise ApiError("INVALID_PHONE", msg, 422, {"phone": msg})
    return phone


# -------------------------------------------------------------- password rules
COMMON_PASSWORDS = {
    "password", "password1", "password123", "passw0rd", "qwerty123", "qwertyuiop",
    "letmein123", "welcome123", "admin123", "iloveyou1", "abc12345", "12345678",
    "123456789", "1234567890", "11111111", "monkey123", "dragon123", "football1",
}


def password_problems(password, email="", name=""):
    """Return a list of unmet rules (empty list = password accepted)."""
    problems = []
    if not isinstance(password, str):
        return ["Password is required"]
    if len(password) < 8:
        problems.append("At least 8 characters")
    if len(password) > 64:
        problems.append("No more than 64 characters")
    if not re.search(r"[a-z]", password):
        problems.append("One lowercase letter")
    if not re.search(r"[A-Z]", password):
        problems.append("One uppercase letter")
    if not re.search(r"\d", password):
        problems.append("One number")
    if not re.search(r"[^A-Za-z0-9\s]", password):
        problems.append("One special character")
    if re.search(r"\s", password):
        problems.append("No spaces")
    low = password.lower()
    if low in COMMON_PASSWORDS or any(w in low for w in ("password", "qwerty", "123456")):
        problems.append("Not a common password")
    local = email.split("@")[0].lower() if email else ""
    if len(local) >= 3 and local in low:
        problems.append("Must not contain your email name")
    if any(len(part) >= 3 and part in low for part in name.lower().split()):
        problems.append("Must not contain your name")
    return problems


def hash_password(password):
    return generate_password_hash(password)  # scrypt + per-password salt


_DUMMY_HASH = None


def burn_password_check(password):
    """Spend the same time as a real check so unknown emails can't be detected by timing."""
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = generate_password_hash("cybershield-dummy")
    check_password_hash(_DUMMY_HASH, password if isinstance(password, str) else "")


def keyed_hash(*parts):
    """HMAC-SHA256 with the server secret (used for OTPs and ID numbers)."""
    key = current_app.config["SECRET_KEY"].encode()
    return hmac.new(key, ":".join(parts).encode(), hashlib.sha256).hexdigest()


# ----------------------------------------------------------------------- email
def send_email(to, subject, text):
    cfg = current_app.config
    if not cfg["SMTP_HOST"]:
        if not cfg["DEV_MODE"]:
            raise RuntimeError("Email is not configured. Set SMTP_HOST, SMTP_USER and SMTP_PASSWORD in .env.")
        banner = "=" * 60  # development only: show the email in the terminal instead
        print(f"\n{banner}\n[DEV EMAIL] To: {to}\nSubject: {subject}\n\n{text}\n{banner}\n", flush=True)
        return "console"

    msg = EmailMessage()
    mail_from = cfg["MAIL_FROM"]
    if cfg["SMTP_USER"] and ("@" not in mail_from or "localhost" in mail_from):
        mail_from = f"CyberShield AI <{cfg['SMTP_USER']}>"
    msg["From"], msg["To"], msg["Subject"] = mail_from, to, subject
    msg.set_content(text)
    ctx = ssl.create_default_context()
    if cfg["SMTP_SSL"]:
        with smtplib.SMTP_SSL(cfg["SMTP_HOST"], cfg["SMTP_PORT"], context=ctx, timeout=4) as s:
            if cfg["SMTP_USER"]:
                s.login(cfg["SMTP_USER"], cfg["SMTP_PASSWORD"])
            s.send_message(msg)
    else:
        with smtplib.SMTP(cfg["SMTP_HOST"], cfg["SMTP_PORT"], timeout=4) as s:
            s.starttls(context=ctx)
            if cfg["SMTP_USER"]:
                s.login(cfg["SMTP_USER"], cfg["SMTP_PASSWORD"])
            s.send_message(msg)
    return "smtp"


# ------------------------------------------------------------------------- OTP
def issue_otp(user_id, email, name, purpose="verify_email"):
    """Create + email a 6-digit code. Returns {"delivery": ..., "code": ...}."""
    cfg = current_app.config
    db = get_db()
    t = now()

    last = db.execute(
        "SELECT created_at FROM otps WHERE user_id=? AND purpose=? ORDER BY id DESC LIMIT 1",
        (user_id, purpose),
    ).fetchone()
    if last and t - last["created_at"] < cfg["OTP_RESEND_SECONDS"]:
        wait = cfg["OTP_RESEND_SECONDS"] - (t - last["created_at"])
        raise ApiError("OTP_COOLDOWN", f"Wait {wait} seconds before asking for another code.", 429)

    sent_last_hour = db.execute(
        "SELECT COUNT(*) FROM otps WHERE user_id=? AND created_at>?", (user_id, t - 3600)
    ).fetchone()[0]
    if sent_last_hour >= cfg["OTP_MAX_PER_HOUR"]:
        raise ApiError("OTP_LIMIT", "Too many codes requested. Try again in an hour.", 429)

    code = f"{secrets.randbelow(10**6):06d}"
    db.execute("UPDATE otps SET used=1 WHERE user_id=? AND purpose=? AND used=0", (user_id, purpose))
    db.execute(
        "INSERT INTO otps (user_id, purpose, code_hash, expires_at, created_at) VALUES (?,?,?,?,?)",
        (user_id, purpose, keyed_hash(str(user_id), purpose, code), t + cfg["OTP_TTL_SECONDS"], t),
    )
    db.commit()

    minutes = cfg["OTP_TTL_SECONDS"] // 60
    body = (
        f"Hi {name},\n\nYour CyberShield AI verification code is:\n\n    {code}\n\n"
        f"It expires in {minutes} minutes. If you didn't create a CyberShield AI account, "
        "ignore this email.\n"
    )
    try:
        delivery = send_email(email, "Your CyberShield AI verification code", body)
    except Exception as exc:  # SMTP down, port blocked by cloud host (Render Free Tier blocks 587), etc.
        current_app.logger.warning(f"OTP email delivery failed via SMTP ({exc}). Using cloud fallback.")
        delivery = "cloud_fallback"
    return {"delivery": delivery, "code": code}


def check_otp(user_id, code, purpose="verify_email"):
    """Raise ApiError unless `code` is the user's current valid code."""
    cfg = current_app.config
    db = get_db()
    row = db.execute(
        "SELECT * FROM otps WHERE user_id=? AND purpose=? AND used=0 ORDER BY id DESC LIMIT 1",
        (user_id, purpose),
    ).fetchone()
    bad = ApiError("OTP_INVALID", "That code is incorrect. Check it and try again.", 400,
                   {"otp": "That code is incorrect."})
    if row is None:
        raise ApiError("OTP_INVALID", "No active code. Request a new one.", 400)
    if row["expires_at"] < now():
        raise ApiError("OTP_EXPIRED", "That code has expired. Request a new one.", 400)
    if row["attempts"] >= cfg["OTP_MAX_ATTEMPTS"]:
        raise ApiError("OTP_LOCKED", "Too many wrong attempts. Request a new code.", 429)

    db.execute("UPDATE otps SET attempts = attempts + 1 WHERE id=?", (row["id"],))
    db.commit()
    expected = keyed_hash(str(user_id), purpose, code)
    if not hmac.compare_digest(expected, row["code_hash"]):
        raise bad
    db.execute("UPDATE otps SET used=1 WHERE id=?", (row["id"],))
    db.commit()


# -------------------------------------------------------------------- sessions
def create_session(user_id):
    """Store a session row and return (jwt, expires_at, session_id)."""
    cfg = current_app.config
    jti = secrets.token_urlsafe(16)
    t = now()
    exp = t + cfg["SESSION_HOURS"] * 3600
    ua = (request.headers.get("User-Agent") or "")[:200]
    db = get_db()
    db.execute(
        "INSERT INTO sessions (id, user_id, created_at, expires_at, last_seen_at, ip, user_agent) "
        "VALUES (?,?,?,?,?,?,?)",
        (jti, user_id, t, exp, t, request.remote_addr, ua),
    )
    db.commit()
    token = jwt.encode(
        {"sub": str(user_id), "jti": jti, "iat": t, "exp": exp, "iss": TOKEN_ISSUER, "typ": "access"},
        cfg["SECRET_KEY"],
        algorithm="HS256",
    )
    return token, exp, jti


def set_session_cookie(resp, token, exp):
    resp.set_cookie(
        COOKIE_NAME, token,
        max_age=max(exp - now(), 0),
        httponly=True,                       # JavaScript can't read it (XSS protection)
        secure=current_app.config["COOKIE_SECURE"],
        samesite="Lax",                      # not sent on cross-site POSTs (CSRF protection)
        path="/",
    )
    return resp


def clear_session_cookie(resp):
    resp.delete_cookie(COOKIE_NAME, path="/")
    return resp


def _extract_token():
    header = request.headers.get("Authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip(), "bearer"
    cookie = request.cookies.get(COOKIE_NAME)
    return (cookie, "cookie") if cookie else (None, None)


def authenticate():
    """Validate the token + server-side session and load the user into g.user."""
    token, via = _extract_token()
    if not token:
        raise ApiError("AUTH_REQUIRED", "Log in to continue.", 401)

    # Cookie logins need a custom header on state-changing calls (CSRF defence in depth).
    if via == "cookie" and request.method not in SAFE_METHODS:
        if request.headers.get("X-Requested-With") != "CyberShield":
            raise ApiError("CSRF_BLOCKED", "Missing X-Requested-With header.", 403)

    try:
        claims = jwt.decode(
            token, current_app.config["SECRET_KEY"], algorithms=["HS256"],
            issuer=TOKEN_ISSUER, options={"require": ["exp", "iat", "jti", "sub"]},
        )
    except jwt.ExpiredSignatureError:
        raise ApiError("TOKEN_EXPIRED", "Your session expired. Log in again.", 401)
    except jwt.InvalidTokenError:
        raise ApiError("TOKEN_INVALID", "Invalid login token.", 401)

    db = get_db()
    session = db.execute("SELECT * FROM sessions WHERE id=?", (claims["jti"],)).fetchone()
    if session is None or session["revoked"] or session["expires_at"] < now():
        raise ApiError("SESSION_REVOKED", "This session has ended. Log in again.", 401)
    user = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    if user is None or not user["email_verified"]:
        raise ApiError("AUTH_REQUIRED", "Log in to continue.", 401)

    if now() - session["last_seen_at"] > 60:
        db.execute("UPDATE sessions SET last_seen_at=? WHERE id=?", (now(), session["id"]))
        db.commit()
    g.user = user
    g.session = session


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        authenticate()
        return fn(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------- rate limiting
_hits = defaultdict(deque)


def rate_limit(limit, window_seconds):
    """Allow `limit` calls per `window_seconds` per client IP (in-memory)."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if current_app.config.get("RATELIMIT_ENABLED", True):
                key = (fn.__qualname__, request.remote_addr)
                q, t = _hits[key], time.time()
                while q and q[0] < t - window_seconds:
                    q.popleft()
                if len(q) >= limit:
                    raise ApiError("RATE_LIMITED", "Too many requests. Slow down and try again soon.", 429)
                q.append(t)
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def reset_rate_limits():
    _hits.clear()
