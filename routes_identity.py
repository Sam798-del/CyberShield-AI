import json
import re
import secrets

from flask import Blueprint, current_app, g, request

from db import get_db
from identity_docs import DOC_TYPES, names_overlap, normalize_number, validate_document
from responses import ApiError, get_json, ok
from security import clean_name, keyed_hash, login_required, now, rate_limit
from services import (
    DEFAULT_PRIVACY_SWITCHES, assess_breach, calculate_account_risk, compute_identity_metrics,
    compute_trust, generate_identity_recommendations, get_identity_activity_log,
    load_settings, log_identity_activity, save_setting, seed_demo_accounts_if_empty,
    validate_bool_map,
)

bp = Blueprint("identity", __name__, url_prefix="/api/identity")


# ------------------------------------------------------------------ helpers
def _account_json(r):
    breach_info = None
    if r["breach_details"]:
        try:
            breach_info = json.loads(r["breach_details"])
        except Exception:
            breach_info = None

    breach_badge = "Clear"
    if r["breach_status"] == "exposed":
        if breach_info and breach_info.get("year"):
            breach_badge = f"Exposed {breach_info['year']}"
        else:
            breach_badge = "Exposed"

    return {
        "id": r["id"],
        "account_name": r["account_name"],
        "account_type": r["account_type"],
        "identifier": r["identifier"],
        "password_health": r["password_health"],
        "is_2fa_enabled": bool(r["is_2fa_enabled"]),
        "breach_status": r["breach_status"],
        "breach_badge": breach_badge,
        "breach_details": breach_info,
        "last_checked_at": r["last_checked_at"],
        "risk_level": r["risk_level"],
        "notes": r["notes"] or "",
        "created_at": r["created_at"],
        "updated_at": r["updated_at"],
    }


def _get_accounts_for_user(user_id):
    rows = get_db().execute(
        "SELECT * FROM linked_accounts WHERE user_id=? ORDER BY created_at DESC", (user_id,)
    ).fetchall()
    return [_account_json(r) for r in rows]


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


# ------------------------------------------------------------------ overview
@bp.get("")
@login_required
def overview():
    """
    Main Digital Identity Hub:
    Returns the user's Identity Risk Score, linked accounts inventory,
    2FA coverage tracker, exposure breakdown, prioritized recommendations, and activity log.
    Every user gets their own unique, isolated information.
    """
    user_id = g.user["id"]
    accounts = _get_accounts_for_user(user_id)
    metrics = compute_identity_metrics(accounts)
    recs = generate_identity_recommendations(accounts)
    activity = get_identity_activity_log(user_id)
    settings = load_settings(user_id)

    return ok({
        "user": {"name": g.user["name"], "email": g.user["email"], "email_verified": True},
        "identity_risk": metrics,
        "accounts": accounts,
        "recommendations": recs,
        "activity_log": activity,
        "stats": metrics["stats"],
        # Backwards compatibility
        "trust": compute_trust(g.user),
        "credentials": _credentials(user_id),
        "privacy_switches": settings["privacy_switches"],
        "doc_types": [{"id": k, "label": v} for k, v in DOC_TYPES.items()],
    })


# ---------------------------------------------------------- linked accounts CRUD
VALID_TYPES = {"social", "email", "phone", "shopping", "work", "finance", "other"}
VALID_PW_HEALTH = {"strong", "medium", "weak", "reused", "sso"}


def validate_service_name(name):
    clean = (name or "").strip()
    if not clean or len(clean) < 2 or len(clean) > 50:
        raise ApiError("INVALID_NAME", "Service name must be between 2 and 50 characters.", 422,
                       {"account_name": "Enter a valid service or account name (2-50 characters)."})
    if not re.search(r"[a-zA-Z]", clean):
        raise ApiError("INVALID_NAME", "Service name must contain alphabetic characters.", 422,
                       {"account_name": "Service name must contain letters."})
    if re.search(r"[<>{}\\/\x00-\x1f]", clean):
        raise ApiError("INVALID_NAME", "Service name contains disallowed characters.", 422,
                       {"account_name": "No HTML or special symbols allowed."})
    return clean


def validate_account_identifier(account_type, identifier):
    val = (identifier or "").strip()
    if not val:
        raise ApiError("INVALID_IDENTIFIER", "Account identifier cannot be empty.", 422,
                       {"identifier": "Enter a valid email, phone number, or handle."})

    email_pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    clean_digits = re.sub(r"[\s\-\(\)]", "", val)
    phone_pattern = r"^\+?[1-9]\d{7,14}$"

    if account_type == "email":
        if not re.fullmatch(email_pattern, val) or len(val) < 6:
            raise ApiError("INVALID_EMAIL", "Enter a true, valid email address (e.g. name@domain.com).", 422,
                           {"identifier": "Enter a valid email address (e.g. name@domain.com)."})
        domain = val.split("@")[1]
        if "." not in domain or len(domain.split(".")[-1]) < 2:
            raise ApiError("INVALID_EMAIL", "Enter an email with a valid top-level domain (e.g. .com, .org).", 422,
                           {"identifier": "Invalid email domain extension."})
        return val.lower()

    elif account_type == "phone":
        if not re.fullmatch(phone_pattern, clean_digits) or len(clean_digits.lstrip("+")) < 10:
            raise ApiError("INVALID_PHONE", "Enter a true phone number with at least 10 digits.", 422,
                           {"identifier": "Phone number must have at least 10 digits."})
        return val

    else:
        # Social, shopping, work, finance, etc.
        is_email = bool(re.fullmatch(email_pattern, val))
        is_phone = bool(re.fullmatch(phone_pattern, clean_digits)) and len(clean_digits.lstrip("+")) >= 10
        is_handle = bool(re.fullmatch(r"^@?[a-zA-Z0-9_.]{3,35}$", val))
        if not (is_email or is_phone or is_handle):
            raise ApiError("INVALID_IDENTIFIER", "Enter a true email, phone number, or valid profile username.", 422,
                           {"identifier": "Must be a valid email, phone number, or handle (@username)."})
        return val


@bp.post("/accounts")
@login_required
def add_account():
    data = get_json()
    account_type = (data.get("account_type") or "other").strip().lower()
    if account_type not in VALID_TYPES:
        account_type = "other"

    account_name = validate_service_name(data.get("account_name"))
    identifier = validate_account_identifier(account_type, data.get("identifier"))

    password_health = (data.get("password_health") or "medium").strip().lower()
    if password_health not in VALID_PW_HEALTH:
        password_health = "medium"

    is_2fa = 1 if data.get("is_2fa_enabled") else 0
    notes = (data.get("notes") or "").strip()

    # Reject duplicate accounts
    db = get_db()
    existing = db.execute(
        "SELECT id FROM linked_accounts WHERE user_id=? AND LOWER(account_name)=? AND LOWER(identifier)=?",
        (g.user["id"], account_name.lower(), identifier.lower())
    ).fetchone()
    if existing:
        raise ApiError("DUPLICATE_ACCOUNT", f"You have already added this {account_name} account.", 409,
                       {"identifier": f"This {account_name} account is already in your inventory."})

    # Breach assessment (authentic breach intelligence)
    assessment = assess_breach(account_name, identifier)
    breach_status = assessment["status"]
    breach_details = json.dumps(assessment["info"]) if assessment["info"] else None

    # Calculate per-account risk
    risk_level = calculate_account_risk(breach_status, password_health, is_2fa, account_type)

    t = now()
    cur = db.execute(
        """INSERT INTO linked_accounts 
           (user_id, account_name, account_type, identifier, password_health, is_2fa_enabled, 
            breach_status, breach_details, last_checked_at, risk_level, notes, created_at, updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            g.user["id"], account_name, account_type, identifier, password_health, is_2fa,
            breach_status, breach_details, t, risk_level, notes, t, t,
        ),
    )
    db.commit()

    # Log activity
    log_identity_activity(g.user["id"], f"Linked authenticated account: {account_name}", f"Type: {account_type.capitalize()} \u00b7 {identifier}")

    row = db.execute("SELECT * FROM linked_accounts WHERE id=?", (cur.lastrowid,)).fetchone()
    account = _account_json(row)

    accounts = _get_accounts_for_user(g.user["id"])
    metrics = compute_identity_metrics(accounts)

    return ok({
        "account": account,
        "identity_risk": metrics,
        "recommendations": generate_identity_recommendations(accounts),
        "activity_log": get_identity_activity_log(g.user["id"]),
    }, 201)


@bp.put("/accounts/<int:acc_id>")
@login_required
def update_account(acc_id):
    db = get_db()
    row = db.execute("SELECT * FROM linked_accounts WHERE id=? AND user_id=?", (acc_id, g.user["id"])).fetchone()
    if not row:
        raise ApiError("NOT_FOUND", "Account not found.", 404)

    data = get_json()
    account_type = (data.get("account_type", row["account_type"])).strip().lower()
    if account_type not in VALID_TYPES:
        account_type = row["account_type"]

    account_name = validate_service_name(data.get("account_name", row["account_name"]))
    identifier = validate_account_identifier(account_type, data.get("identifier", row["identifier"]))
    password_health = (data.get("password_health", row["password_health"])).strip().lower()
    if password_health not in VALID_PW_HEALTH:
        password_health = row["password_health"]

    is_2fa = 1 if data.get("is_2fa_enabled", bool(row["is_2fa_enabled"])) else 0
    notes = data.get("notes", row["notes"] or "")

    # Breach status may be updated or maintained
    breach_status = data.get("breach_status", row["breach_status"])
    breach_details = row["breach_details"]

    if "breach_status" in data and data["breach_status"] == "clear":
        breach_status = "clear"
        breach_details = None
    elif account_name != row["account_name"] or identifier != row["identifier"]:
        assessment = assess_breach(account_name, identifier)
        breach_status = assessment["status"]
        breach_details = json.dumps(assessment["info"]) if assessment["info"] else None

    risk_level = calculate_account_risk(breach_status, password_health, is_2fa, account_type)
    t = now()

    db.execute(
        """UPDATE linked_accounts 
           SET account_name=?, account_type=?, identifier=?, password_health=?, is_2fa_enabled=?, 
               breach_status=?, breach_details=?, risk_level=?, notes=?, updated_at=?
           WHERE id=? AND user_id=?""",
        (
            account_name, account_type, identifier, password_health, is_2fa,
            breach_status, breach_details, risk_level, notes, t, acc_id, g.user["id"],
        ),
    )
    db.commit()

    # Track meaningful action logs
    if not row["is_2fa_enabled"] and is_2fa:
        log_identity_activity(g.user["id"], f"Turned on 2FA for {account_name}", "Enhanced login protection")
    elif row["password_health"] != password_health:
        log_identity_activity(g.user["id"], f"Updated password health for {account_name}", f"Status: {password_health}")
    elif row["breach_status"] == "exposed" and breach_status == "clear":
        log_identity_activity(g.user["id"], f"Resolved breach risk on {account_name}", "Marked password changed & cleared")
    else:
        log_identity_activity(g.user["id"], f"Updated {account_name} details")

    updated_row = db.execute("SELECT * FROM linked_accounts WHERE id=?", (acc_id,)).fetchone()
    account = _account_json(updated_row)

    accounts = _get_accounts_for_user(g.user["id"])
    metrics = compute_identity_metrics(accounts)

    return ok({
        "account": account,
        "identity_risk": metrics,
        "recommendations": generate_identity_recommendations(accounts),
        "activity_log": get_identity_activity_log(g.user["id"]),
    })


@bp.delete("/accounts/<int:acc_id>")
@login_required
def delete_account(acc_id):
    db = get_db()
    row = db.execute("SELECT * FROM linked_accounts WHERE id=? AND user_id=?", (acc_id, g.user["id"])).fetchone()
    if not row:
        raise ApiError("NOT_FOUND", "Account not found.", 404)

    acc_name = row["account_name"]
    db.execute("DELETE FROM linked_accounts WHERE id=? AND user_id=?", (acc_id, g.user["id"]))
    db.commit()

    log_identity_activity(g.user["id"], f"Removed {acc_name}", "Removed from digital identity inventory")

    accounts = _get_accounts_for_user(g.user["id"])
    metrics = compute_identity_metrics(accounts)

    return ok({
        "deleted": True,
        "identity_risk": metrics,
        "recommendations": generate_identity_recommendations(accounts),
        "activity_log": get_identity_activity_log(g.user["id"]),
    })


@bp.post("/accounts/<int:acc_id>/recheck")
@login_required
def recheck_account(acc_id):
    """Re-runs breach check against this account and updates last checked time."""
    db = get_db()
    row = db.execute("SELECT * FROM linked_accounts WHERE id=? AND user_id=?", (acc_id, g.user["id"])).fetchone()
    if not row:
        raise ApiError("NOT_FOUND", "Account not found.", 404)

    assessment = assess_breach(row["account_name"], row["identifier"])
    breach_status = assessment["status"]
    breach_details = json.dumps(assessment["info"]) if assessment["info"] else None
    risk_level = calculate_account_risk(breach_status, row["password_health"], row["is_2fa_enabled"], row["account_type"])
    t = now()

    db.execute(
        """UPDATE linked_accounts 
           SET breach_status=?, breach_details=?, risk_level=?, last_checked_at=?, updated_at=?
           WHERE id=? AND user_id=?""",
        (breach_status, breach_details, risk_level, t, t, acc_id, g.user["id"]),
    )
    db.commit()

    log_identity_activity(g.user["id"], f"Re-checked {row['account_name']}", f"Breach status: {assessment['badge']}")

    updated_row = db.execute("SELECT * FROM linked_accounts WHERE id=?", (acc_id,)).fetchone()
    account = _account_json(updated_row)

    accounts = _get_accounts_for_user(g.user["id"])
    metrics = compute_identity_metrics(accounts)

    return ok({
        "account": account,
        "identity_risk": metrics,
        "recommendations": generate_identity_recommendations(accounts),
        "activity_log": get_identity_activity_log(g.user["id"]),
    })


@bp.post("/recheck-all")
@login_required
def recheck_all():
    """Runs a simulated breach & security scan over all accounts the user owns."""
    user_id = g.user["id"]
    db = get_db()
    rows = db.execute("SELECT * FROM linked_accounts WHERE user_id=?", (user_id,)).fetchall()
    t = now()

    for r in rows:
        assessment = assess_breach(r["account_name"], r["identifier"])
        breach_status = assessment["status"]
        breach_details = json.dumps(assessment["info"]) if assessment["info"] else None
        risk_level = calculate_account_risk(breach_status, r["password_health"], r["is_2fa_enabled"], r["account_type"])
        db.execute(
            """UPDATE linked_accounts 
               SET breach_status=?, breach_details=?, risk_level=?, last_checked_at=?, updated_at=?
               WHERE id=?""",
            (breach_status, breach_details, risk_level, t, t, r["id"]),
        )
    db.commit()

    log_identity_activity(user_id, "Re-checked all linked accounts", f"Refreshed threat intelligence for {len(rows)} accounts")

    accounts = _get_accounts_for_user(user_id)
    metrics = compute_identity_metrics(accounts)

    return ok({
        "accounts": accounts,
        "identity_risk": metrics,
        "recommendations": generate_identity_recommendations(accounts),
        "activity_log": get_identity_activity_log(user_id),
    })


@bp.post("/seed-demo")
@login_required
def seed_demo():
    """Reset or load starter demo accounts."""
    db = get_db()
    db.execute("DELETE FROM linked_accounts WHERE user_id=?", (g.user["id"],))
    db.commit()
    seed_demo_accounts_if_empty(g.user["id"], g.user["email"], g.user["name"])

    accounts = _get_accounts_for_user(g.user["id"])
    metrics = compute_identity_metrics(accounts)

    return ok({
        "accounts": accounts,
        "identity_risk": metrics,
        "recommendations": generate_identity_recommendations(accounts),
        "activity_log": get_identity_activity_log(g.user["id"]),
    })


# ------------------------------------------------------------------ credentials (Legacy)
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
        switches["share_masked_numbers"] = False
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
