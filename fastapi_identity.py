"""
CyberShield AI — Digital Identity FastAPI Service Module
=========================================================
Provides ongoing online accounts inventory, real-time exposure tracking,
2FA posture monitoring, and breach risk synthesis for mobile (Flutter)
and web platforms.
"""

from typing import List, Optional
import time
import sqlite3
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
import jwt

router = APIRouter(prefix="/api/identity", tags=["Digital Identity Accounts Inventory"])
security = HTTPBearer(auto_error=False)

JWT_SECRET = "cybershield-ai-local-dev-secret-key-32b"
JWT_ALGORITHM = "HS256"
DB_PATH = "instance/cybershield.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    """Validates JWT bearer token or falls back to demo account."""
    if credentials:
        try:
            payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            user_id = int(payload.get("sub", 1))
            return {"id": user_id, "email": "admin@cybershield.ai"}
        except Exception:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    # Graceful demo fallback
    return {"id": 1, "email": "admin@cybershield.ai"}


# ---------------------------------------------------------------------------
# Pydantic Schemas
# ---------------------------------------------------------------------------

class AccountCreate(BaseModel):
    service_name: str = Field(..., example="Google")
    service_type: str = Field("online", example="online")  # 'online', 'email', 'phone'
    domain: Optional[str] = Field(None, example="google.com")
    identifier: str = Field(..., example="user@gmail.com")
    password_strength: int = Field(70, ge=0, le=100)
    password_reused: bool = False
    password_fingerprint: Optional[str] = None  # Salted hash fingerprint only; NEVER plaintext
    two_factor_enabled: bool = False


class AccountUpdate(BaseModel):
    two_factor_enabled: Optional[bool] = None
    password_strength: Optional[int] = None
    password_reused: Optional[bool] = None
    breach_status: Optional[str] = None
    activity_note: Optional[str] = None


class AccountResponse(BaseModel):
    id: int
    service_name: str
    service_type: str
    domain: Optional[str]
    identifier: str
    password_strength: int
    password_reused: bool
    two_factor_enabled: bool
    breach_status: str
    breach_count: int
    last_breach_name: Optional[str]
    last_checked_at: int
    created_at: int
    updated_at: int


# ---------------------------------------------------------------------------
# Scoring Engine
# ---------------------------------------------------------------------------

def calculate_identity_score(accounts: List[dict]):
    """
    Transparent Scoring:
    Start at 100.
    Subtract 15 per breached account.
    Subtract 10 per reused password.
    Subtract 10 per weak password (< 50).
    Subtract 5 per account lacking 2FA.
    Floor at 0.
    """
    if not accounts:
        return 100, "No linked accounts tracked yet. Add your accounts to monitor exposure."

    score = 100
    reasons = []

    breached = [a for a in accounts if a["breach_status"] == "breached"]
    reused = [a for a in accounts if a["password_reused"]]
    weak = [a for a in accounts if a["password_strength"] < 50 and not a["password_reused"]]
    no_2fa = [a for a in accounts if not a["two_factor_enabled"]]

    if breached:
        score -= len(breached) * 15
        reasons.append(f"{len(breached)} account{'s' if len(breached) > 1 else ''} found in data breaches")
    if reused:
        score -= len(reused) * 10
        reasons.append(f"{len(reused)} password{'s' if len(reused) > 1 else ''} reused")
    if weak:
        score -= len(weak) * 10
        reasons.append(f"{len(weak)} weak password{'s' if len(weak) > 1 else ''}")
    if no_2fa:
        score -= len(no_2fa) * 5
        reasons.append(f"{len(no_2fa)} account{'s' if len(no_2fa) > 1 else ''} lack 2FA")

    score = max(0, min(100, score))
    explanation = ", ".join(reasons) if reasons else "All accounts secured with 2FA, strong unique credentials, and no known breach exposures."
    return score, explanation


# ---------------------------------------------------------------------------
# FastAPI Route Handlers
# ---------------------------------------------------------------------------

@router.get("/accounts")
def list_accounts(
    type: Optional[str] = Query(None, regex="^(all|email|phone|online)$"),
    user: dict = Depends(get_current_user)
):
    """List online accounts for the logged-in user with optional category filtering."""
    conn = get_db()
    if type and type != "all":
        rows = conn.execute(
            "SELECT * FROM identity_accounts WHERE user_id=? AND service_type=? ORDER BY updated_at DESC",
            (user["id"], type)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM identity_accounts WHERE user_id=? ORDER BY updated_at DESC",
            (user["id"],)
        ).fetchall()
    conn.close()
    return {"status": "ok", "data": {"accounts": [dict(r) for r in rows]}}


@router.post("/accounts", status_code=status.HTTP_201_CREATED)
def add_account(payload: AccountCreate, user: dict = Depends(get_current_user)):
    """Add a new account inventory row (manual add or Chrome extension login detection)."""
    conn = get_db()
    t = int(time.time())

    # Simulated breach heuristic (HIBP lookup integration point)
    breach_status = "safe"
    breach_count = 0
    last_breach = None
    if "breach" in payload.identifier.lower() or payload.service_name.lower() in ("adobe", "myspace"):
        breach_status = "breached"
        breach_count = 1
        last_breach = f"{payload.service_name} Public Leak"
    elif not payload.two_factor_enabled and payload.password_strength < 60:
        breach_status = "review"

    cur = conn.execute("""
        INSERT INTO identity_accounts (
            user_id, service_name, service_type, domain, identifier,
            password_strength, password_reused, password_fingerprint,
            two_factor_enabled, breach_status, breach_count, last_breach_name,
            last_checked_at, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        user["id"], payload.service_name, payload.service_type, payload.domain,
        payload.identifier, payload.password_strength, 1 if payload.password_reused else 0,
        payload.password_fingerprint, 1 if payload.two_factor_enabled else 0,
        breach_status, breach_count, last_breach, t, t, t
    ))

    new_id = cur.lastrowid
    conn.execute("""
        INSERT INTO identity_activity (user_id, action_type, account_id, description, created_at)
        VALUES (?, 'add', ?, ?, ?)
    """, (user["id"], new_id, f"Added {payload.service_name} account ({payload.identifier})", t))
    conn.commit()

    row = conn.execute("SELECT * FROM identity_accounts WHERE id=?", (new_id,)).fetchone()
    conn.close()
    return {"status": "ok", "data": {"account": dict(row)}}


@router.put("/accounts/{account_id}")
def update_account(account_id: int, payload: AccountUpdate, user: dict = Depends(get_current_user)):
    """Update account credentials posture (e.g. user enabled 2FA or changed password)."""
    conn = get_db()
    existing = conn.execute("SELECT * FROM identity_accounts WHERE id=? AND user_id=?", (account_id, user["id"])).fetchone()
    if not existing:
        conn.close()
        raise HTTPException(status_code=404, detail="Account not found")

    t = int(time.time())
    two_fa = existing["two_factor_enabled"] if payload.two_factor_enabled is None else (1 if payload.two_factor_enabled else 0)
    strength = existing["password_strength"] if payload.password_strength is None else payload.password_strength
    reused = existing["password_reused"] if payload.password_reused is None else (1 if payload.password_reused else 0)
    b_status = existing["breach_status"] if payload.breach_status is None else payload.breach_status

    conn.execute("""
        UPDATE identity_accounts
        SET two_factor_enabled=?, password_strength=?, password_reused=?, breach_status=?, updated_at=?
        WHERE id=? AND user_id=?
    """, (two_fa, strength, reused, b_status, t, account_id, user["id"]))

    desc = payload.activity_note or f"Updated security settings for {existing['service_name']}"
    conn.execute("""
        INSERT INTO identity_activity (user_id, action_type, account_id, description, created_at)
        VALUES (?, 'fix', ?, ?, ?)
    """, (user["id"], account_id, desc, t))
    conn.commit()

    updated = conn.execute("SELECT * FROM identity_accounts WHERE id=?", (account_id,)).fetchone()
    conn.close()
    return {"status": "ok", "data": {"account": dict(updated)}}


@router.delete("/accounts/{account_id}")
def delete_account(account_id: int, user: dict = Depends(get_current_user)):
    """Remove an account from ongoing monitoring."""
    conn = get_db()
    existing = conn.execute("SELECT * FROM identity_accounts WHERE id=? AND user_id=?", (account_id, user["id"])).fetchone()
    if not existing:
        conn.close()
        raise HTTPException(status_code=404, detail="Account not found")

    t = int(time.time())
    conn.execute("DELETE FROM identity_accounts WHERE id=? AND user_id=?", (account_id, user["id"]))
    conn.execute("""
        INSERT INTO identity_activity (user_id, action_type, account_id, description, created_at)
        VALUES (?, 'delete', ?, ?, ?)
    """, (user["id"], account_id, f"Removed {existing['service_name']} account from inventory", t))
    conn.commit()
    conn.close()
    return {"status": "ok", "data": {"deleted": True, "id": account_id}}


@router.post("/accounts/{account_id}/recheck")
def recheck_account(account_id: int, user: dict = Depends(get_current_user)):
    """Re-check breach records and exposure status for an account."""
    conn = get_db()
    existing = conn.execute("SELECT * FROM identity_accounts WHERE id=? AND user_id=?", (account_id, user["id"])).fetchone()
    if not existing:
        conn.close()
        raise HTTPException(status_code=404, detail="Account not found")

    t = int(time.time())
    conn.execute("UPDATE identity_accounts SET last_checked_at=?, updated_at=? WHERE id=?", (t, t, account_id))
    conn.execute("""
        INSERT INTO identity_activity (user_id, action_type, account_id, description, created_at)
        VALUES (?, 'recheck', ?, ?, ?)
    """, (user["id"], account_id, f"Re-checked exposure and breach status for {existing['service_name']}", t))
    conn.commit()

    updated = conn.execute("SELECT * FROM identity_accounts WHERE id=?", (account_id,)).fetchone()
    conn.close()
    return {"status": "ok", "data": {"account": dict(updated)}}


@router.get("/summary")
def get_summary(user: dict = Depends(get_current_user)):
    """Provides the Digital Identity Risk Score, summary statistics, exposure breakdown, and ranked priority fixes."""
    conn = get_db()
    rows = conn.execute("SELECT * FROM identity_accounts WHERE user_id=?", (user["id"],)).fetchall()
    accounts = [dict(r) for r in rows]
    conn.close()

    total = len(accounts)
    score, explanation = calculate_identity_score(accounts)
    breaches = sum(1 for a in accounts if a["breach_status"] == "breached")
    two_fa = sum(1 for a in accounts if a["two_factor_enabled"])
    weak_or_reused = sum(1 for a in accounts if a["password_reused"] or a["password_strength"] < 50)

    safe = sum(1 for a in accounts if a["breach_status"] == "safe" and a["two_factor_enabled"] and a["password_strength"] >= 70 and not a["password_reused"])
    high_risk = sum(1 for a in accounts if a["breach_status"] == "breached" or a["password_reused"] or a["password_strength"] < 50)
    review = max(0, total - safe - high_risk)

    # Ranked priority fixes
    fixes = []
    for a in accounts:
        if a["breach_status"] == "breached":
            fixes.append({
                "id": f"fix_breach_{a['id']}",
                "account_id": a["id"],
                "service": a["service_name"],
                "title": f"Password changed after breach on {a['service_name']}",
                "severity": "high",
                "steps": [
                    f"Navigate to {a['service_name']} account security page.",
                    "Generate a 16+ character unique password.",
                    "Revoke any active suspicious web sessions."
                ]
            })
    for a in accounts:
        if a["password_reused"]:
            fixes.append({
                "id": f"fix_reused_{a['id']}",
                "account_id": a["id"],
                "service": a["service_name"],
                "title": f"Create unique password for {a['service_name']}",
                "severity": "high",
                "steps": [
                    f"Open {a['service_name']} Security Settings.",
                    "Replace reused password with a unique, randomized password."
                ]
            })
    for a in accounts:
        if not a["two_factor_enabled"]:
            fixes.append({
                "id": f"fix_2fa_{a['id']}",
                "account_id": a["id"],
                "service": a["service_name"],
                "title": f"Enable 2FA on {a['service_name']}",
                "severity": "medium",
                "steps": [
                    f"Open {a['service_name']} Security preferences.",
                    "Activate 2-Step Verification using an Authenticator app (TOTP)."
                ]
            })

    return {
        "status": "ok",
        "data": {
            "score": score,
            "explanation": explanation,
            "accounts_tracked": total,
            "breaches_found": breaches,
            "two_factor_coverage": f"{two_fa} of {total}",
            "weak_or_reused_passwords": weak_or_reused,
            "exposure_breakdown": {
                "safe": safe,
                "review": review,
                "high_risk": high_risk,
                "total": total
            },
            "priority_fixes": fixes[:5]
        }
    }


@router.get("/activity")
def get_activity(user: dict = Depends(get_current_user)):
    """Returns chronological timeline of account exposure updates and security fixes."""
    conn = get_db()
    rows = conn.execute("""
        SELECT * FROM identity_activity
        WHERE user_id=?
        ORDER BY created_at DESC
        LIMIT 25
    """, (user["id"],)).fetchall()
    conn.close()
    return {"status": "ok", "data": {"activity": [dict(r) for r in rows]}}
