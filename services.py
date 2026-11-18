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
