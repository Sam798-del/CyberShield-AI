"""Per-user settings and the identity trust score."""
import json

from db import get_db
from responses import ApiError
from security import now

# ----------------------------------------------------------------- defaults
DEFAULT_PRIVACY_SWITCHES = {
    "share_name": True,
    "share_email": False,
    "share_trust_score": True,
    "share_verified_documents": False,   # which document types are verified
    "share_masked_numbers": False,       # last 4 digits (only if documents are shared)
}

SENSITIVITY_PRESETS = {"relaxed": 80, "balanced": 60, "strict": 35}
DEFAULT_THRESHOLDS = {"phishing": 60, "cyberbullying": 60, "password": 60, "leak": 60}

# The extension / AI teammates can rename these to match the real models they use.
AVAILABLE_AI_MODELS = [
    {"id": "fast", "label": "Fast", "description": "Quickest answers, lighter analysis."},
    {"id": "balanced", "label": "Balanced", "description": "Good speed and accuracy for everyday use."},
    {"id": "thorough", "label": "Thorough", "description": "Deepest analysis, slower responses."},
]
DEFAULT_AI_MODEL = "balanced"

RETENTION_CHOICES = [7, 30, 90, 365]
DEFAULT_PRIVACY_CONTROLS = {
    "save_scan_history": True,
    "history_retention_days": 30,
    "share_anonymous_analytics": False,
    "mask_sensitive_text_in_logs": True,
    "allow_extension_access": True,
}


def _merge(defaults, stored):
    merged = dict(defaults)
    merged.update({k: v for k, v in (stored or {}).items() if k in defaults})
    return merged


def create_default_settings(user_id):
    get_db().execute(
        "INSERT OR IGNORE INTO settings (user_id, privacy_switches, thresholds, ai_model, privacy_controls) "
        "VALUES (?,?,?,?,?)",
        (user_id, json.dumps(DEFAULT_PRIVACY_SWITCHES), json.dumps(DEFAULT_THRESHOLDS),
         DEFAULT_AI_MODEL, json.dumps(DEFAULT_PRIVACY_CONTROLS)),
    )


def load_settings(user_id):
    db = get_db()
    row = db.execute("SELECT * FROM settings WHERE user_id=?", (user_id,)).fetchone()
    if row is None:
        create_default_settings(user_id)
        db.commit()
        row = db.execute("SELECT * FROM settings WHERE user_id=?", (user_id,)).fetchone()
    return {
        "privacy_switches": _merge(DEFAULT_PRIVACY_SWITCHES, json.loads(row["privacy_switches"])),
        "thresholds": _merge(DEFAULT_THRESHOLDS, json.loads(row["thresholds"])),
        "ai_model": row["ai_model"],
        "privacy_controls": _merge(DEFAULT_PRIVACY_CONTROLS, json.loads(row["privacy_controls"])),
    }


def save_setting(user_id, column, value):
    assert column in {"privacy_switches", "thresholds", "ai_model", "privacy_controls"}
    stored = json.dumps(value) if column != "ai_model" else value
    db = get_db()
    db.execute(f"UPDATE settings SET {column}=? WHERE user_id=?", (stored, user_id))
    db.commit()


# --------------------------------------------------------------- validation
def validate_bool_map(data, defaults, label):
    """Accept only known keys with real booleans."""
    if not isinstance(data, dict) or not data:
        raise ApiError("BAD_REQUEST", f"Send the {label} you want to change.", 400)
    unknown = [k for k in data if k not in defaults]
    if unknown:
        raise ApiError("UNKNOWN_FIELD", f"Unknown {label}: {', '.join(unknown)}.", 422)
    clean = {}
    for key, value in data.items():
        if not isinstance(value, bool):
            raise ApiError("INVALID_VALUE", f"{key} must be true or false.", 422, {key: "Use true or false."})
        clean[key] = value
    return clean


# -------------------------------------------------------------- trust score
def compute_trust(user):
    """Transparent 0-100 score built from real account data."""
    db = get_db()
    t = now()
    creds = db.execute(
        "SELECT * FROM credentials WHERE user_id=? AND status='verified'", (user["id"],)
    ).fetchall()

    parts = []

    def add(key, label, earned, maximum, note):
        parts.append({"key": key, "label": label, "earned": earned, "max": maximum, "note": note})

    add("email", "Email verified", 20 if user["email_verified"] else 0, 20,
        "Verified with a one-time code" if user["email_verified"] else "Verify your email")

    doc_points = {0: 0, 1: 25, 2: 40}.get(len(creds), 50)
    add("documents", "Verified documents", doc_points, 50,
        f"{len(creds)} verified" + ("" if creds else " - add an ID document"))

    name_ok = any(c["name_matches"] for c in creds)
    add("name_match", "Name matches a document", 10 if name_ok else 0, 10,
        "Document name matches your account name" if name_ok else "No document matches your account name yet")

    age_days = (t - user["created_at"]) // 86400
    add("account_age", "Account age", min(10, age_days // 3), 10, f"{age_days} days old")

    recent = bool(user["last_login_at"]) and t - user["last_login_at"] <= 30 * 86400
    add("recent_activity", "Recent activity", 10 if recent else 0, 10,
        "Logged in within 30 days" if recent else "No login in the last 30 days")

    score = sum(p["earned"] for p in parts)
    level = "high" if score >= 70 else "medium" if score >= 40 else "low"
    return {"score": score, "level": level, "breakdown": parts}


# ==============================================================
# DIGITAL IDENTITY: WHO AM I ONLINE? (Linked Accounts & Risk Engine)
# ==============================================================

KNOWN_BREACHES = {
    "instagram": {
        "source": "Instagram Third-Party Scrape & API Leak",
        "year": "2023",
        "date": "March 2023",
        "data_classes": ["Email addresses", "Phone numbers", "Usernames", "Bio details"],
        "severity": "High",
        "description": "Scraped records containing user contact details and profile identifiers were compiled and leaked on breach forums.",
    },
    "linkedin": {
        "source": "LinkedIn Global Data Scraping Leak",
        "year": "2021",
        "date": "June 2021",
        "data_classes": ["Email addresses", "Phone numbers", "Full names", "Professional records"],
        "severity": "High",
        "description": "Records representing over 700 million accounts were extracted via API abuse and published online.",
    },
    "canva": {
        "source": "Canva Database Breach",
        "year": "2019",
        "date": "May 2019",
        "data_classes": ["Passwords (bcrypt)", "Email addresses", "Real names", "Locations"],
        "severity": "Critical",
        "description": "137 million user accounts were compromised by Gnosticplayers, exposing encrypted credentials and emails.",
    },
    "adobe": {
        "source": "Adobe Systems Massive Compromise",
        "year": "2013",
        "date": "October 2013",
        "data_classes": ["Encrypted passwords", "Password hints", "Email addresses"],
        "severity": "Critical",
        "description": "153 million user records were stolen, including reversible password hashes and plain hints.",
    },
    "twitter": {
        "source": "Twitter Public API Data Exfiltration",
        "year": "2023",
        "date": "January 2023",
        "data_classes": ["Email addresses", "Screen names", "Creation timestamps"],
        "severity": "High",
        "description": "Over 200 million user records matching email addresses to handles were leaked publicly.",
    },
    "dropbox": {
        "source": "Dropbox Credential Stuffing Breach",
        "year": "2016",
        "date": "August 2016",
        "data_classes": ["Email addresses", "Hashed passwords"],
        "severity": "High",
        "description": "68 million user login credentials from previous stuffing attacks were confirmed and dumped.",
    },
}


def assess_breach(account_name, identifier):
    """Check account against simulated HIBP-style breach intelligence."""
    norm_name = (account_name or "").strip().lower()
    norm_id = (identifier or "").strip().lower()

    for key, info in KNOWN_BREACHES.items():
        if key in norm_name or key in norm_id:
            return {
                "status": "exposed",
                "badge": f"Exposed {info['year']}",
                "info": info,
            }

    # Common demo/sample triggers for testing in viva/presentations
    if "breach" in norm_id or "leak" in norm_id or "exposed" in norm_id or "test" in norm_id:
        return {
            "status": "exposed",
            "badge": "Exposed 2023",
            "info": {
                "source": "Collection / Dark Web Credential Dump",
                "year": "2023",
                "date": "November 2023",
                "data_classes": ["Email addresses", "Compromised passwords", "Device identifiers"],
                "severity": "High",
                "description": "Credentials matched records indexed from global credential-stuffing databases.",
            },
        }

    return {"status": "clear", "badge": "Clear", "info": None}


def calculate_account_risk(breach_status, password_health, is_2fa_enabled, account_type):
    """
    Categorizes account into Safe, Need Review, or High Risk.
    No plaintext passwords are ever checked or stored.
    """
    is_breached = (breach_status == "exposed")
    is_weak_pw = password_health in ("weak", "reused")
    has_2fa = bool(is_2fa_enabled)

    if is_breached:
        # Breached + weak/reused password or no 2FA = High Risk
        if is_weak_pw or not has_2fa:
            return "high"
        return "review"

    # Not breached
    if password_health == "weak":
        return "high" if not has_2fa else "review"
    if password_health == "reused":
        return "review"
    if not has_2fa and account_type in ("email", "social", "finance", "shopping"):
        return "review"
    if password_health == "strong" and has_2fa:
        return "safe"

    return "safe" if has_2fa else "review"


def compute_identity_metrics(accounts):
    """
    Builds the Identity Risk Score (0-100, where higher means higher risk/exposure),
    2FA coverage stats, exposure breakdown, and dynamic explanation.
    """
    total = len(accounts)
    if total == 0:
        return {
            "score": 0,
            "level": "low",
            "summary": "No accounts linked yet. Add accounts to evaluate your identity risk.",
            "stats": {
                "total": 0,
                "safe": 0,
                "review": 0,
                "high": 0,
                "two_fa_enabled": 0,
                "two_fa_percentage": 0,
            },
        }

    safe_count = sum(1 for a in accounts if a["risk_level"] == "safe")
    review_count = sum(1 for a in accounts if a["risk_level"] == "review")
    high_count = sum(1 for a in accounts if a["risk_level"] == "high")

    two_fa_count = sum(1 for a in accounts if a["is_2fa_enabled"])
    two_fa_pct = round((two_fa_count / total) * 100)

    breached_count = sum(1 for a in accounts if a["breach_status"] == "exposed")
    weak_pw_count = sum(1 for a in accounts if a["password_health"] in ("weak", "reused"))
    no_2fa_count = total - two_fa_count

    # Risk Score calculation (0 = completely safe, 100 = critical exposure)
    # 1. Breach exposure: up to 35 points
    breach_factor = (breached_count / total) * 35
    # 2. 2FA deficiency: up to 30 points
    two_fa_factor = (no_2fa_count / total) * 30
    # 3. Password health weakness: up to 25 points
    pw_factor = (weak_pw_count / total) * 25
    # 4. Critical risk ratio: up to 10 points
    high_factor = (high_count / total) * 10

    raw_score = breach_factor + two_fa_factor + pw_factor + high_factor
    score = min(100, max(0, round(raw_score)))

    # Level label
    if score >= 70 or high_count >= 2:
        level = "high"
    elif score >= 35 or review_count >= 1 or high_count >= 1:
        level = "medium"
    else:
        level = "low"

    # Short explanatory line e.g. "2 accounts lack 2FA, 1 password reused"
    parts = []
    if no_2fa_count > 0:
        parts.append(f"{no_2fa_count} account{'s lack' if no_2fa_count > 1 else ' lacks'} 2FA")
    if weak_pw_count > 0:
        parts.append(f"{weak_pw_count} password{'s' if weak_pw_count > 1 else ''} weak or reused")
    if breached_count > 0:
        parts.append(f"{breached_count} account{'s' if breached_count > 1 else ''} exposed in breaches")

    if parts:
        summary = ", ".join(parts)
    else:
        summary = "All linked accounts are protected with 2FA and unique strong passwords."

    return {
        "score": score,
        "level": level,
        "summary": summary,
        "stats": {
            "total": total,
            "safe": safe_count,
            "review": review_count,
            "high": high_count,
            "two_fa_enabled": two_fa_count,
            "two_fa_percentage": two_fa_pct,
        },
    }


def generate_identity_recommendations(accounts):
    """Generates prioritized recommendations ranked by security impact."""
    if not accounts:
        return [
            {
                "id": "onboarding_1",
                "account_id": None,
                "account_name": "Primary Email",
                "priority": 1,
                "impact": "High Impact",
                "badge": "First Step",
                "title": "Link your primary email address",
                "detail": "Add your primary Gmail or personal email to scan for past breach exposures.",
                "action": "add_account",
            },
            {
                "id": "onboarding_2",
                "account_id": None,
                "account_name": "Social / Phone",
                "priority": 2,
                "impact": "Medium Impact",
                "badge": "Recommended",
                "title": "Add your phone number and main social accounts",
                "detail": "Track which of your active profiles are protected with Two-Factor Authentication (2FA).",
                "action": "add_account",
            },
        ]

    recs = []

    # Priority 1: Breached account with weak/reused password (Critical)
    for a in accounts:
        if a["breach_status"] == "exposed" and a["password_health"] in ("weak", "reused"):
            recs.append({
                "id": f"breach_pw_{a['id']}",
                "account_id": a["id"],
                "account_name": a["account_name"],
                "priority": 1,
                "impact": "High Impact",
                "badge": "Critical",
                "title": f"Change the compromised password for {a['account_name']}",
                "detail": f"This account was exposed in a past breach ({a.get('breach_badge') or 'Exposed'}) and uses a weak or reused password.",
                "action": "fix_breach",
            })

    # Priority 2: Missing 2FA on high-value accounts (Email, Social, Banking, Shopping)
    for a in accounts:
        if not a["is_2fa_enabled"] and a["account_type"] in ("email", "social", "finance", "shopping"):
            recs.append({
                "id": f"2fa_{a['id']}",
                "account_id": a["id"],
                "account_name": a["account_name"],
                "priority": 2,
                "impact": "High Impact",
                "badge": "Recommended",
                "title": f"Turn on 2FA for {a['account_name']}",
                "detail": "Adding two-factor authentication blocks 99% of automated credential attacks.",
                "action": "fix_2fa",
            })

    # Priority 3: Reused passwords without known breach
    for a in accounts:
        if a["password_health"] == "reused" and a["breach_status"] != "exposed":
            recs.append({
                "id": f"pw_reused_{a['id']}",
                "account_id": a["id"],
                "account_name": a["account_name"],
                "priority": 3,
                "impact": "Medium Impact",
                "badge": "Review",
                "title": f"Replace reused password on {a['account_name']}",
                "detail": "Reusing passwords means a breach on one website can compromise this account too.",
                "action": "fix_password",
            })

    # Priority 4: Weak passwords
    for a in accounts:
        if a["password_health"] == "weak" and a["breach_status"] != "exposed":
            recs.append({
                "id": f"pw_weak_{a['id']}",
                "account_id": a["id"],
                "account_name": a["account_name"],
                "priority": 4,
                "impact": "Medium Impact",
                "badge": "Review",
                "title": f"Upgrade weak password on {a['account_name']}",
                "detail": "Short or simple passwords can be cracked by automated brute-force tools.",
                "action": "fix_password",
            })

    # Priority 5: Missing 2FA on other accounts
    for a in accounts:
        if not a["is_2fa_enabled"] and a["account_type"] not in ("email", "social", "finance", "shopping"):
            recs.append({
                "id": f"2fa_other_{a['id']}",
                "account_id": a["id"],
                "account_name": a["account_name"],
                "priority": 5,
                "impact": "Low Impact",
                "badge": "Good Practice",
                "title": f"Enable 2FA on {a['account_name']}",
                "detail": "Protect secondary and utility accounts from unauthorized logins.",
                "action": "fix_2fa",
            })

    # Priority 6: Clean-up recommendation
    if len(accounts) >= 4:
        recs.append({
            "id": "audit_old_accounts",
            "account_id": None,
            "account_name": "Old Accounts",
            "priority": 6,
            "impact": "Low Impact",
            "badge": "Hygiene",
            "title": "Review and remove dormant accounts you no longer use",
            "detail": "Unused accounts create an unnecessary digital footprint and exposure surface.",
            "action": "audit",
        })

    # Sort strictly by priority
    recs.sort(key=lambda r: r["priority"])
    return recs[:5]


def log_identity_activity(user_id, action, detail=None):
    """Record an audit trail event for digital identity progress."""
    db = get_db()
    db.execute(
        "INSERT INTO identity_activity_log (user_id, action, detail, created_at) VALUES (?,?,?,?)",
        (user_id, action, detail, now()),
    )
    db.commit()


def get_identity_activity_log(user_id, limit=8):
    """Retrieve recent change log entries for the user."""
    rows = get_db().execute(
        "SELECT * FROM identity_activity_log WHERE user_id=? ORDER BY created_at DESC LIMIT ?",
        (user_id, limit),
    ).fetchall()
    return [{"id": r["id"], "action": r["action"], "detail": r["detail"], "created_at": r["created_at"]} for r in rows]


def seed_demo_accounts_if_empty(user_id, user_email, user_name):
    """
    Populates realistic starter accounts matching the assignment spec
    (Instagram, Gmail, LinkedIn, Amazon, College email) so each user has
    tangible, rich data to inspect and present immediately.
    """
    db = get_db()
    existing = db.execute("SELECT COUNT(*) AS c FROM linked_accounts WHERE user_id=?", (user_id,)).fetchone()
    if existing and existing["c"] > 0:
        return

    t = now()
    sample_accounts = [
        {
            "account_name": "Instagram",
            "account_type": "social",
            "identifier": user_email or "user@gmail.com",
            "password_health": "weak",
            "is_2fa_enabled": 0,
            "breach_status": "exposed",
            "breach_details": json.dumps({
                "source": "Instagram Scraped Credential Leak",
                "year": "2023",
                "date": "March 2023",
                "data_classes": ["Passwords", "Email addresses", "Phone numbers"],
                "severity": "High",
                "description": "Records containing user account references and phone numbers leaked online.",
            }),
            "last_checked_at": t - 2 * 86400,
            "risk_level": "high",
            "notes": "Main social profile",
        },
        {
            "account_name": "Google / Gmail",
            "account_type": "email",
            "identifier": user_email or "user@gmail.com",
            "password_health": "reused",
            "is_2fa_enabled": 1,
            "breach_status": "exposed",
            "breach_details": json.dumps({
                "source": "Collection #1 Compilation",
                "year": "2021",
                "date": "January 2021",
                "data_classes": ["Email addresses", "Compromised passwords"],
                "severity": "High",
                "description": "Older credentials detected in large-scale breach dumps.",
            }),
            "last_checked_at": t - 1 * 86400,
            "risk_level": "review",
            "notes": "Primary email hub",
        },
        {
            "account_name": "LinkedIn",
            "account_type": "social",
            "identifier": user_email or "user@gmail.com",
            "password_health": "strong",
            "is_2fa_enabled": 1,
            "breach_status": "clear",
            "breach_details": None,
            "last_checked_at": t - 3 * 86400,
            "risk_level": "safe",
            "notes": "Professional network",
        },
        {
            "account_name": "Amazon",
            "account_type": "shopping",
            "identifier": "+91 98765 43210",
            "password_health": "weak",
            "is_2fa_enabled": 0,
            "breach_status": "clear",
            "breach_details": None,
            "last_checked_at": t - 5 * 86400,
            "risk_level": "high",
            "notes": "Online orders and card storage",
        },
        {
            "account_name": "College / University Email",
            "account_type": "email",
            "identifier": "student@college.edu",
            "password_health": "strong",
            "is_2fa_enabled": 0,
            "breach_status": "clear",
            "breach_details": None,
            "last_checked_at": t - 7 * 86400,
            "risk_level": "review",
            "notes": "Academic portal and campus services",
        },
    ]

    for acc in sample_accounts:
        db.execute(
            """INSERT INTO linked_accounts 
               (user_id, account_name, account_type, identifier, password_health, is_2fa_enabled, 
                breach_status, breach_details, last_checked_at, risk_level, notes, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                user_id, acc["account_name"], acc["account_type"], acc["identifier"],
                acc["password_health"], acc["is_2fa_enabled"], acc["breach_status"],
                acc["breach_details"], acc["last_checked_at"], acc["risk_level"],
                acc["notes"], t - 14 * 86400, t,
            ),
        )

    # Initial activity log entries
    log_identity_activity(user_id, "Connected primary Gmail identity", "Linked with 2-step verification")
    log_identity_activity(user_id, "Added Instagram account", "Identified breach exposure from 2023")
    log_identity_activity(user_id, "Connected LinkedIn profile", "Protected with 2FA")
    db.commit()

