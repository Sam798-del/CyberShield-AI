import re

from flask import Blueprint, current_app, g

from db import get_db
from responses import ApiError, get_json, ok
from security import (
    burn_password_check, check_otp, clean_name, clear_session_cookie, create_session,
    hash_password, issue_otp, login_required, normalize_email, now, password_problems,
    rate_limit, set_session_cookie,
)
from services import create_default_settings
from werkzeug.security import check_password_hash

bp = Blueprint("auth", __name__, url_prefix="/api/auth")


def public_user(u):
    return {
        "id": u["id"], "name": u["name"], "email": u["email"],
        "email_verified": bool(u["email_verified"]), "phone": u["phone"],
        "created_at": u["created_at"],
    }


def _otp_payload(result, email):
    cfg = current_app.config
    data = {
        "email": email, "otp_required": True,
        "otp_expires_in": cfg["OTP_TTL_SECONDS"], "delivery": result["delivery"],
    }
    if cfg["DEV_MODE"]:
        data["dev_otp"] = result["code"]  # only in development
    return data


def _session_response(user, status=200, extra=None):
    token, exp, _jti = create_session(user["id"])
    body = {"token": token, "token_type": "Bearer", "expires_at": exp, "user": public_user(user)}
    body.update(extra or {})
    return set_session_cookie(ok(body, status), token, exp)


@bp.post("/signup")
@rate_limit(10, 3600)
def signup():
    data = get_json()
    name = clean_name(data.get("name"))
    email = normalize_email(data.get("email"))
    password = data.get("password")
    problems = password_problems(password, email, name)
    if problems:
        raise ApiError("WEAK_PASSWORD", "That password doesn't meet the rules.", 422, {"password": problems})

    db = get_db()
    existing = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if existing and existing["email_verified"]:
        msg = "An account with this email already exists. Log in instead."
        raise ApiError("EMAIL_TAKEN", msg, 409, {"email": msg})

    if existing:  # unfinished sign-up: let them restart with new details
        user_id = existing["id"]
        db.execute("UPDATE users SET name=?, password_hash=? WHERE id=?",
                   (name, hash_password(password), user_id))
    else:
        cur = db.execute(
            "INSERT INTO users (name, email, password_hash, created_at) VALUES (?,?,?,?)",
            (name, email, hash_password(password), now()),
        )
        user_id = cur.lastrowid
        create_default_settings(user_id)
    db.commit()

    result = issue_otp(user_id, email, name)
    return ok(_otp_payload(result, email), 201)


@bp.post("/resend-otp")
@rate_limit(10, 3600)
def resend_otp():
    email = normalize_email(get_json().get("email"))
    user = get_db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if user and not user["email_verified"]:
        result = issue_otp(user["id"], email, user["name"])
        return ok(_otp_payload(result, email))
    # Same answer either way so this can't be used to discover registered emails.
    return ok({"email": email, "otp_required": True, "otp_expires_in": current_app.config["OTP_TTL_SECONDS"]})


@bp.post("/verify-otp")
@rate_limit(20, 900)
def verify_otp():
    data = get_json()
    email = normalize_email(data.get("email"))
    code = str(data.get("otp") or "").strip()
    if not re.fullmatch(r"\d{6}", code):
        raise ApiError("OTP_INVALID", "Enter the 6-digit code.", 422, {"otp": "Enter the 6-digit code."})

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if user is None:
        raise ApiError("OTP_INVALID", "That code is incorrect or has expired.", 400)
    check_otp(user["id"], code)
    db.execute("UPDATE users SET email_verified=1, last_login_at=? WHERE id=?", (now(), user["id"]))
    db.commit()
    user = db.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
    return _session_response(user)


@bp.post("/login")
@rate_limit(15, 900)
def login():
    cfg = current_app.config
    data = get_json()
    email = normalize_email(data.get("email"))
    password = data.get("password")
    wrong = ApiError("INVALID_CREDENTIALS", "Incorrect email or password.", 401)

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if user is None:
        burn_password_check(password)
        raise wrong

    if user["locked_until"] > now():
        mins = max(1, (user["locked_until"] - now() + 59) // 60)
        raise ApiError("ACCOUNT_LOCKED", f"Too many failed attempts. Try again in {mins} min.", 423)

    if not isinstance(password, str) or not check_password_hash(user["password_hash"], password):
        failed = user["failed_logins"] + 1
        if failed >= cfg["MAX_FAILED_LOGINS"]:
            db.execute("UPDATE users SET failed_logins=0, locked_until=? WHERE id=?",
                       (now() + cfg["LOCKOUT_SECONDS"], user["id"]))
        else:
            db.execute("UPDATE users SET failed_logins=? WHERE id=?", (failed, user["id"]))
        db.commit()
        raise wrong

    if not user["email_verified"]:
        try:
            issue_otp(user["id"], email, user["name"])
        except ApiError:
            pass  # a code was sent moments ago; the old one still works
        raise ApiError("EMAIL_NOT_VERIFIED", "Verify your email to continue. We sent you a code.", 403,
                       {"email": email})

    db.execute("UPDATE users SET failed_logins=0, locked_until=0, last_login_at=? WHERE id=?",
               (now(), user["id"]))
    db.commit()
    user = db.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
    return _session_response(user)


@bp.post("/logout")
@login_required
def logout():
    db = get_db()
    db.execute("UPDATE sessions SET revoked=1 WHERE id=?", (g.session["id"],))
    db.commit()
    return clear_session_cookie(ok({"logged_out": True}))


@bp.post("/logout-all")
@login_required
def logout_all():
    db = get_db()
    db.execute("UPDATE sessions SET revoked=1 WHERE user_id=?", (g.user["id"],))
    db.commit()
    return clear_session_cookie(ok({"logged_out": True}))


@bp.get("/me")
@login_required
def me():
    return ok({"user": public_user(g.user), "session": {"id": g.session["id"], "expires_at": g.session["expires_at"]}})


@bp.get("/verify-token")
@login_required
def verify_token():
    """For the extension and other features: who is logged in?"""
    return ok({
        "valid": True, "user_id": g.user["id"], "name": g.user["name"],
        "email": g.user["email"], "expires_at": g.session["expires_at"],
    })


@bp.get("/sessions")
@login_required
def list_sessions():
    rows = get_db().execute(
        "SELECT * FROM sessions WHERE user_id=? AND revoked=0 AND expires_at>? ORDER BY last_seen_at DESC",
        (g.user["id"], now()),
    ).fetchall()
    return ok({"sessions": [
        {"id": r["id"], "created_at": r["created_at"], "last_seen_at": r["last_seen_at"],
         "ip": r["ip"], "user_agent": r["user_agent"], "current": r["id"] == g.session["id"]}
        for r in rows
    ]})


@bp.delete("/sessions/<session_id>")
@login_required
def revoke_session(session_id):
    db = get_db()
    cur = db.execute("UPDATE sessions SET revoked=1 WHERE id=? AND user_id=?", (session_id, g.user["id"]))
    db.commit()
    if cur.rowcount == 0:
        raise ApiError("NOT_FOUND", "Session not found.", 404)
    return ok({"revoked": True})
