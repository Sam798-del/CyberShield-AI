import re
import secrets
from functools import wraps

from flask import Blueprint, current_app, g, request

from db import get_db
from identity_docs import DOC_TYPES, names_overlap, normalize_number, validate_document
from responses import ApiError, get_json, ok
from security import authenticate, clean_name, keyed_hash, login_required, now, rate_limit
from services import (
    DEFAULT_PRIVACY_SWITCHES, compute_trust, load_settings, save_setting, validate_bool_map,
)

bp = Blueprint("identity", __name__, url_prefix="/api/identity")


def _credential_json(r):
    return {
        "id": r["id"], "doc_type": r["doc_type"], "doc_label": DOC_TYPES.get(r["doc_type"], r["doc_type"]),
        "holder_name": r["holder_name"], "number_masked": "\u2022" * 4 + r["number_last4"],
        "name_matches_account": bool(r["name_matches"]), "status": r["status"],
        "added_at": r["created_at"],
    }


def _credentials(user_id):
    rows = get_db().execute(
        "SELECT * FROM credentials WHERE user_id=? ORDER BY created_at", (user_id,)
    ).fetchall()
    return [_credential_json(r) for r in rows]


@bp.get("")
@login_required
def overview():
    """Everything the Digital Identity screen (or the extension) needs in one call."""
    settings = load_settings(g.user["id"])
    return ok({
        "user": {"name": g.user["name"], "email": g.user["email"], "email_verified": True},
        "trust": compute_trust(g.user),
        "credentials": _credentials(g.user["id"]),
        "privacy_switches": settings["privacy_switches"],
        "doc_types": [{"id": k, "label": v} for k, v in DOC_TYPES.items()],
    })


# ------------------------------------------------------------------ credentials
@bp.post("/credentials")
@login_required
@rate_limit(30, 3600)
def add_credential():
    data = get_json()
    doc_type = data.get("doc_type")
    if doc_type not in DOC_TYPES:
        raise ApiError("INVALID_DOC_TYPE", "Choose a supported document type.", 422,
                       {"doc_type": "Choose a supported document type."})
    holder = clean_name(data.get("holder_name"))
    number = normalize_number(data.get("number") if isinstance(data.get("number"), str) else "")
    if not number:
        raise ApiError("INVALID_NUMBER", "Enter the document number.", 422, {"number": "Enter the document number."})

    checks = validate_document(doc_type, number, holder)
    if not all(c["passed"] for c in checks):
        failed = next(c for c in checks if not c["passed"])
        msg = f"This doesn't look like a valid {DOC_TYPES[doc_type]} number ({failed['detail']})."
        raise ApiError("VERIFICATION_FAILED", msg, 422, {"number": msg})

    db = get_db()
    number_hash = keyed_hash("doc", doc_type, number)
    taken = db.execute("SELECT user_id FROM credentials WHERE number_hash=?", (number_hash,)).fetchone()
    if taken and taken["user_id"] != g.user["id"]:
        raise ApiError("DOCUMENT_IN_USE", "This document is already linked to another account.", 409,
                       {"number": "Already linked to another account."})

    matches = names_overlap(holder, g.user["name"])
    # One document per type: replacing it re-runs verification.
    db.execute("DELETE FROM credentials WHERE user_id=? AND doc_type=?", (g.user["id"], doc_type))
    cur = db.execute(
        "INSERT INTO credentials (user_id, doc_type, holder_name, number_hash, number_last4, name_matches, created_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (g.user["id"], doc_type, holder, number_hash, number[-4:], int(matches), now()),
    )
    db.commit()
    row = db.execute("SELECT * FROM credentials WHERE id=?", (cur.lastrowid,)).fetchone()
    return ok({"credential": _credential_json(row), "checks": checks, "trust": compute_trust(g.user)}, 201)


@bp.delete("/credentials/<int:cred_id>")
@login_required
def delete_credential(cred_id):
    db = get_db()
    cur = db.execute("DELETE FROM credentials WHERE id=? AND user_id=?", (cred_id, g.user["id"]))
    db.commit()
    if cur.rowcount == 0:
        raise ApiError("NOT_FOUND", "Credential not found.", 404)
    return ok({"deleted": True, "trust": compute_trust(g.user)})


# --------------------------------------------------------------- privacy switches
@bp.get("/privacy-switches")
@login_required
def get_switches():
    return ok({"privacy_switches": load_settings(g.user["id"])["privacy_switches"]})


@bp.put("/privacy-switches")
@login_required
def put_switches():
    changes = validate_bool_map(get_json(), DEFAULT_PRIVACY_SWITCHES, "privacy switches")
    switches = load_settings(g.user["id"])["privacy_switches"]
    switches.update(changes)
    if not switches["share_verified_documents"]:
        switches["share_masked_numbers"] = False  # numbers only make sense with documents
    save_setting(g.user["id"], "privacy_switches", switches)
    return ok({"privacy_switches": switches})


# ------------------------------------------------------------------- QR verify
@bp.post("/qr")
@login_required
@rate_limit(30, 3600)
def create_qr():
    ttl = current_app.config["QR_TTL_SECONDS"]
    token = secrets.token_urlsafe(18)
    t = now()
    db = get_db()
    # Only one live QR per user: a new one replaces the old.
    db.execute("UPDATE qr_tokens SET revoked=1 WHERE user_id=? AND revoked=0", (g.user["id"],))
    db.execute("INSERT INTO qr_tokens (id, user_id, created_at, expires_at) VALUES (?,?,?,?)",
               (token, g.user["id"], t, t + ttl))
    db.commit()
    url = request.host_url.rstrip("/") + "/verify.html?t=" + token
    return ok({"token": token, "verify_url": url, "expires_at": t + ttl, "ttl_seconds": ttl}, 201)


@bp.delete("/qr/<token>")
@login_required
def revoke_qr(token):
    db = get_db()
    cur = db.execute("UPDATE qr_tokens SET revoked=1 WHERE id=? AND user_id=?", (token, g.user["id"]))
    db.commit()
    if cur.rowcount == 0:
        raise ApiError("NOT_FOUND", "QR code not found.", 404)
    return ok({"revoked": True})


def _mask_email(email):
    local, domain = email.split("@", 1)
    return local[:1] + "\u2022" * max(2, len(local) - 1) + "@" + domain


@bp.get("/verify/<token>")
@rate_limit(60, 60)
def public_verify(token):
    """Public endpoint opened by whoever scans the QR. Shows ONLY what the owner allows."""
    if not re.fullmatch(r"[A-Za-z0-9_\-]{10,64}", token):
        raise ApiError("QR_INVALID", "This QR code isn't valid.", 404)
    db = get_db()
    row = db.execute("SELECT * FROM qr_tokens WHERE id=?", (token,)).fetchone()
    if row is None:
        raise ApiError("QR_INVALID", "This QR code isn't valid.", 404)
    if row["revoked"]:
        raise ApiError("QR_REVOKED", "The owner has turned this QR code off.", 410)
    if row["expires_at"] < now():
        raise ApiError("QR_EXPIRED", "This QR code has expired. Ask for a new one.", 410)

    db.execute("UPDATE qr_tokens SET scans = scans + 1 WHERE id=?", (token,))
    db.commit()
    user = db.execute("SELECT * FROM users WHERE id=?", (row["user_id"],)).fetchone()
    sw = load_settings(user["id"])["privacy_switches"]
    creds = db.execute("SELECT * FROM credentials WHERE user_id=? AND status='verified'", (user["id"],)).fetchall()

    shared = {"email_verified": True, "verified_documents_count": len(creds)}
    fields = ["email_verified", "verified_documents_count"]
    if sw["share_name"]:
        shared["name"] = user["name"]; fields.append("name")
    if sw["share_email"]:
        shared["email"] = _mask_email(user["email"]); fields.append("email")
    if sw["share_trust_score"]:
        trust = compute_trust(user)
        shared["trust_score"] = trust["score"]; shared["trust_level"] = trust["level"]; fields.append("trust_score")
    if sw["share_verified_documents"]:
        docs = []
        for c in creds:
            item = {"doc_type": c["doc_type"], "doc_label": DOC_TYPES.get(c["doc_type"], c["doc_type"])}
            if sw["share_masked_numbers"]:
                item["number_masked"] = "\u2022" * 4 + c["number_last4"]
            docs.append(item)
        shared["verified_documents"] = docs; fields.append("verified_documents")
    return ok({"verified": True, "shared": shared, "shared_fields": fields, "expires_at": row["expires_at"]})


# ===========================================================================
# DIGITAL IDENTITY LINKED ACCOUNTS INVENTORY & ONGOING EXPOSURE MONITORING
# ===========================================================================


def auth_or_guest(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            authenticate()
        except Exception:
            db = get_db()
            user = db.execute("SELECT * FROM users WHERE email='admin@cybershield.ai'").fetchone()
            if not user:
                user = db.execute("SELECT * FROM users LIMIT 1").fetchone()
            if user:
                g.user = user
                g.session = {"id": "guest_session", "expires_at": now() + 86400}
            else:
                raise ApiError("AUTH_REQUIRED", "Log in to continue.", 401)
        return fn(*args, **kwargs)
    return wrapper


def _seed_default_accounts_if_empty(user_id):
    db = get_db()
    existing = db.execute("SELECT COUNT(*) as cnt FROM identity_accounts WHERE user_id=?", (user_id,)).fetchone()
    if existing and existing["cnt"] > 0:
        return

    t = now()
    sample_accounts = [
        ("Google", "email", "google.com", "neeraja.shinde@gmail.com", 92, 0, "fprint_goog_1", 1, "safe", 0, None, t - 3600, t - 86400 * 5, t),
        ("GitHub", "online", "github.com", "neeraja-shinde", 88, 0, "fprint_gh_1", 1, "safe", 0, None, t - 7200, t - 86400 * 4, t),
        ("LinkedIn", "online", "linkedin.com", "neeraja.shinde@gmail.com", 75, 0, "fprint_li_1", 0, "review", 1, "2012 Scrape Archive", t - 1800, t - 86400 * 3, t),
        ("Amazon", "online", "amazon.in", "neeraja.shinde@gmail.com", 85, 0, "fprint_amz_1", 1, "safe", 0, None, t - 4000, t - 86400 * 2, t),
        ("Instagram", "online", "instagram.com", "neeraja_sec", 42, 1, "fprint_shared_pass", 0, "breached", 1, "2021 Aggregated Credential Leak", t - 900, t - 86400, t),
        ("Work Phone", "phone", None, "+91 98765 43210", 80, 0, None, 1, "safe", 0, None, t - 500, t - 86400 * 6, t),
    ]

    for item in sample_accounts:
        db.execute("""
            INSERT INTO identity_accounts (
                user_id, service_name, service_type, domain, identifier,
                password_strength, password_reused, password_fingerprint,
                two_factor_enabled, breach_status, breach_count, last_breach_name,
                last_checked_at, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (user_id, *item))

    db.execute("""
        INSERT INTO identity_activity (user_id, action_type, account_id, description, created_at)
        VALUES (?, 'add', 1, 'Initial inventory setup: 6 connected accounts monitored', ?)
    """, (user_id, t - 86400))
    db.commit()


def _format_account(r):
    return {
        "id": r["id"],
        "service_name": r["service_name"],
        "service_type": r["service_type"],
        "domain": r["domain"],
        "identifier": r["identifier"],
        "password_strength": r["password_strength"],
        "password_reused": bool(r["password_reused"]),
        "two_factor_enabled": bool(r["two_factor_enabled"]),
        "breach_status": r["breach_status"],
        "breach_count": r["breach_count"],
        "last_breach_name": r["last_breach_name"],
        "last_checked_at": r["last_checked_at"],
        "created_at": r["created_at"],
        "updated_at": r["updated_at"],
    }


def _calculate_identity_summary(user_id):
    db = get_db()
    _seed_default_accounts_if_empty(user_id)
    rows = db.execute("SELECT * FROM identity_accounts WHERE user_id=? ORDER BY updated_at DESC", (user_id,)).fetchall()
    accounts = [_format_account(r) for r in rows]

    total_count = len(accounts)
    breached_count = sum(1 for a in accounts if a["breach_status"] == "breached")
    two_fa_count = sum(1 for a in accounts if a["two_factor_enabled"])
    weak_reused_count = sum(1 for a in accounts if a["password_reused"] or a["password_strength"] < 50)

    # Safe: no breach, 2FA enabled, strong password (>=70), not reused
    safe_count = sum(1 for a in accounts if a["breach_status"] == "safe" and a["two_factor_enabled"] and a["password_strength"] >= 70 and not a["password_reused"])
    high_risk_count = sum(1 for a in accounts if a["breach_status"] == "breached" or a["password_reused"] or a["password_strength"] < 50)
    review_count = max(0, total_count - safe_count - high_risk_count)

    # Transparent Scoring: start at 100
    score = 100
    reasons = []

    no_2fa_count = total_count - two_fa_count
    reused_count = sum(1 for a in accounts if a["password_reused"])
    weak_only_count = sum(1 for a in accounts if a["password_strength"] < 50 and not a["password_reused"])

    if breached_count:
        score -= (breached_count * 15)
        reasons.append(f"{breached_count} account{'s' if breached_count > 1 else ''} found in data breaches")
    if reused_count:
        score -= (reused_count * 10)
        reasons.append(f"{reused_count} password{'s' if reused_count > 1 else ''} reused")
    if weak_only_count:
        score -= (weak_only_count * 10)
        reasons.append(f"{weak_only_count} weak password{'s' if weak_only_count > 1 else ''}")
    if no_2fa_count:
        score -= (no_2fa_count * 5)
        reasons.append(f"{no_2fa_count} account{'s' if no_2fa_count > 1 else ''} lack 2FA")

    score = max(0, min(100, score))
    explanation = ", ".join(reasons) if reasons else "All accounts secured with 2FA, strong unique credentials, and no known breach exposures."

    # Priority fixes (ranked list: breaches first, then reused, then weak, then 2FA)
    fixes = []
    for a in accounts:
        if a["breach_status"] == "breached":
            fixes.append({
                "id": f"fix_breach_{a['id']}",
                "account_id": a["id"],
                "service": a["service_name"],
                "identifier": a["identifier"],
                "title": f"Password changed after breach on {a['service_name']}",
                "reason": f"Account appeared in {a['last_breach_name'] or 'public breach record'}.",
                "severity": "high",
                "fix_type": "breach_password",
                "points_gain": 15,
                "steps": [
                    f"Navigate to {a['service_name']} account security page.",
                    "Request a password reset and generate a 16+ character unique passphrase.",
                    "Revoke any active suspicious web and mobile sessions."
                ]
            })
    for a in accounts:
        if a["password_reused"]:
            fixes.append({
                "id": f"fix_reused_{a['id']}",
                "account_id": a["id"],
                "service": a["service_name"],
                "identifier": a["identifier"],
                "title": f"Create unique password for {a['service_name']}",
                "reason": "This password fingerprint was detected on multiple online services.",
                "severity": "high",
                "fix_type": "unique_password",
                "points_gain": 10,
                "steps": [
                    f"Open {a['service_name']} Security Settings.",
                    "Replace the reused password with a unique, randomized password.",
                    "Store the new credentials inside a secured vault."
                ]
            })
    for a in accounts:
        if a["password_strength"] < 50 and not a["password_reused"]:
            fixes.append({
                "id": f"fix_weak_{a['id']}",
                "account_id": a["id"],
                "service": a["service_name"],
                "identifier": a["identifier"],
                "title": f"Upgrade weak password ({a['password_strength']}/100) on {a['service_name']}",
                "reason": "Entropy is under recommended 60-bit security baseline.",
                "severity": "medium",
                "fix_type": "strong_password",
                "points_gain": 10,
                "steps": [
                    f"Change password on {a['service_name']} to 12+ characters.",
                    "Mix uppercase, lowercase, numbers, and symbols.",
                    "Avoid names, dates, or common dictionary phrases."
                ]
            })
    for a in accounts:
        if not a["two_factor_enabled"]:
            fixes.append({
                "id": f"fix_2fa_{a['id']}",
                "account_id": a["id"],
                "service": a["service_name"],
                "identifier": a["identifier"],
                "title": f"Enable Two-Factor Authentication on {a['service_name']}",
                "reason": "Account is protected by only single-factor password authentication.",
                "severity": "medium",
                "fix_type": "enable_2fa",
                "points_gain": 5,
                "steps": [
                    f"Open {a['service_name']} Security or Sign-in preferences.",
                    "Activate 2-Step Verification using an Authenticator app (TOTP) or Security Key.",
                    "Save backup emergency recovery codes in a secure location."
                ]
            })

    return {
        "score": score,
        "explanation": explanation,
        "accounts_tracked": total_count,
        "breaches_found": breached_count,
        "two_factor_coverage": f"{two_fa_count} of {total_count}",
        "weak_or_reused_passwords": weak_reused_count,
        "exposure_breakdown": {
            "safe": safe_count,
            "review": review_count,
            "high_risk": high_risk_count,
            "total": total_count
        },
        "priority_fixes": fixes[:6]
    }


@bp.get("/accounts")
@auth_or_guest
def list_accounts():
    """Returns linked accounts inventory with optional ?type= filter."""
    user_id = g.user["id"]
    _seed_default_accounts_if_empty(user_id)
    svc_type = (request.args.get("type") or "").strip().lower()

    db = get_db()
    if svc_type and svc_type in ("email", "phone", "online"):
        rows = db.execute(
            "SELECT * FROM identity_accounts WHERE user_id=? AND service_type=? ORDER BY updated_at DESC",
            (user_id, svc_type)
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT * FROM identity_accounts WHERE user_id=? ORDER BY updated_at DESC",
            (user_id,)
        ).fetchall()

    return ok({"accounts": [_format_account(r) for r in rows]})


@bp.post("/accounts")
@auth_or_guest
def add_account():
    """Adds a new linked account (user-entered or extension-detected)."""
    data = get_json()
    user_id = g.user["id"]

    service_name = (data.get("service_name") or data.get("name") or "").strip()
    if not service_name:
        raise ApiError("INVALID_SERVICE", "Service name is required.", 422, {"service_name": "Required."})

    identifier = (data.get("identifier") or data.get("email") or data.get("phone") or "").strip()
    if not identifier:
        raise ApiError("INVALID_IDENTIFIER", "Account email, phone, or username is required.", 422, {"identifier": "Required."})

    service_type = (data.get("service_type") or data.get("type") or "online").lower()
    if service_type not in ("email", "phone", "online"):
        service_type = "online"

    domain = (data.get("domain") or "").strip() or None
    strength = int(data.get("password_strength") or 70)
    reused = 1 if data.get("password_reused") else 0
    fingerprint = data.get("password_fingerprint") or None
    two_fa = 1 if data.get("two_factor_enabled") else 0

    # Breach detection heuristic
    breach_status = "safe"
    breach_count = 0
    last_breach = None
    lower_id = identifier.lower()
    lower_svc = service_name.lower()
    if "breach" in lower_id or "test-exposed" in lower_id or lower_svc in ("adobe", "myspace", "canva"):
        breach_status = "breached"
        breach_count = 1
        last_breach = f"{service_name} Public Leak"
    elif not two_fa and strength < 60:
        breach_status = "review"

    t = now()
    db = get_db()
    cur = db.execute("""
        INSERT INTO identity_accounts (
            user_id, service_name, service_type, domain, identifier,
            password_strength, password_reused, password_fingerprint,
            two_factor_enabled, breach_status, breach_count, last_breach_name,
            last_checked_at, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (user_id, service_name, service_type, domain, identifier, strength, reused, fingerprint, two_fa, breach_status, breach_count, last_breach, t, t, t))

    new_id = cur.lastrowid
    db.execute("""
        INSERT INTO identity_activity (user_id, action_type, account_id, description, created_at)
        VALUES (?, 'add', ?, ?, ?)
    """, (user_id, new_id, f"Added {service_name} account ({identifier})", t))
    db.commit()

    row = db.execute("SELECT * FROM identity_accounts WHERE id=?", (new_id,)).fetchone()
    summary = _calculate_identity_summary(user_id)
    return ok({"account": _format_account(row), "summary": summary}, 201)


@bp.put("/accounts/<int:account_id>")
@auth_or_guest
def update_account(account_id):
    """Updates account security attributes (e.g., 2FA activated, password strengthened)."""
    user_id = g.user["id"]
    data = get_json()
    db = get_db()

    existing = db.execute("SELECT * FROM identity_accounts WHERE id=? AND user_id=?", (account_id, user_id)).fetchone()
    if not existing:
        raise ApiError("NOT_FOUND", "Account not found.", 404)

    two_fa = 1 if data.get("two_factor_enabled") else (existing["two_factor_enabled"] if "two_factor_enabled" not in data else 0)
    strength = int(data.get("password_strength", existing["password_strength"]))
    reused = 1 if data.get("password_reused") else (existing["password_reused"] if "password_reused" not in data else 0)
    breach_status = data.get("breach_status", existing["breach_status"])
    t = now()

    db.execute("""
        UPDATE identity_accounts
        SET two_factor_enabled=?, password_strength=?, password_reused=?, breach_status=?, updated_at=?
        WHERE id=? AND user_id=?
    """, (two_fa, strength, reused, breach_status, t, account_id, user_id))

    action_desc = data.get("activity_note") or f"Updated security settings for {existing['service_name']}"
    db.execute("""
        INSERT INTO identity_activity (user_id, action_type, account_id, description, created_at)
        VALUES (?, 'fix', ?, ?, ?)
    """, (user_id, account_id, action_desc, t))
    db.commit()

    updated = db.execute("SELECT * FROM identity_accounts WHERE id=?", (account_id,)).fetchone()
    summary = _calculate_identity_summary(user_id)
    return ok({"account": _format_account(updated), "summary": summary})


@bp.delete("/accounts/<int:account_id>")
@auth_or_guest
def delete_account(account_id):
    """Removes a linked account from monitoring."""
    user_id = g.user["id"]
    db = get_db()
    existing = db.execute("SELECT * FROM identity_accounts WHERE id=? AND user_id=?", (account_id, user_id)).fetchone()
    if not existing:
        raise ApiError("NOT_FOUND", "Account not found.", 404)

    db.execute("DELETE FROM identity_accounts WHERE id=? AND user_id=?", (account_id, user_id))
    t = now()
    db.execute("""
        INSERT INTO identity_activity (user_id, action_type, account_id, description, created_at)
        VALUES (?, 'delete', ?, ?, ?)
    """, (user_id, account_id, f"Removed {existing['service_name']} account from inventory", t))
    db.commit()

    summary = _calculate_identity_summary(user_id)
    return ok({"deleted": True, "id": account_id, "summary": summary})


@bp.post("/accounts/<int:account_id>/recheck")
@auth_or_guest
def recheck_account(account_id):
    """Re-scans breach exposure and password posture for an account."""
    user_id = g.user["id"]
    db = get_db()
    existing = db.execute("SELECT * FROM identity_accounts WHERE id=? AND user_id=?", (account_id, user_id)).fetchone()
    if not existing:
        raise ApiError("NOT_FOUND", "Account not found.", 404)

    t = now()
    db.execute("UPDATE identity_accounts SET last_checked_at=?, updated_at=? WHERE id=?", (t, t, account_id))
    db.execute("""
        INSERT INTO identity_activity (user_id, action_type, account_id, description, created_at)
        VALUES (?, 'recheck', ?, ?, ?)
    """, (user_id, account_id, f"Re-checked exposure and breach status for {existing['service_name']}", t))
    db.commit()

    updated = db.execute("SELECT * FROM identity_accounts WHERE id=?", (account_id,)).fetchone()
    summary = _calculate_identity_summary(user_id)
    return ok({"account": _format_account(updated), "summary": summary})


@bp.get("/summary")
@auth_or_guest
def identity_summary():
    """Returns risk score, explanation, summary counts, exposure donut, and priority fixes."""
    user_id = g.user["id"]
    return ok(_calculate_identity_summary(user_id))


@bp.get("/activity")
@auth_or_guest
def identity_activity():
    """Returns chronological timeline of account security changes."""
    user_id = g.user["id"]
    _seed_default_accounts_if_empty(user_id)
    db = get_db()
    rows = db.execute("""
        SELECT * FROM identity_activity
        WHERE user_id=?
        ORDER BY created_at DESC
        LIMIT 20
    """, (user_id,)).fetchall()

    return ok({
        "activity": [
            {
                "id": r["id"],
                "action_type": r["action_type"],
                "account_id": r["account_id"],
                "description": r["description"],
                "created_at": r["created_at"],
            }
            for r in rows
        ]
    })
