import re
import secrets

from flask import Blueprint, current_app, g, request

from db import get_db
from identity_docs import DOC_TYPES, names_overlap, normalize_number, validate_document
from responses import ApiError, get_json, ok
from security import clean_name, keyed_hash, login_required, now, rate_limit
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
