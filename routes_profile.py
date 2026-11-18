from flask import Blueprint, g

from db import get_db
from responses import ApiError, get_json, ok
from security import (
    clean_name, clean_phone, clear_session_cookie, hash_password, login_required, now,
    password_problems, rate_limit,
)
from services import (
    AVAILABLE_AI_MODELS, DEFAULT_PRIVACY_CONTROLS, RETENTION_CHOICES, SENSITIVITY_PRESETS,
    compute_trust, load_settings, save_setting, validate_bool_map,
)
from werkzeug.security import check_password_hash

bp = Blueprint("profile", __name__, url_prefix="/api")


def _account(u):
    return {
        "name": u["name"], "email": u["email"], "phone": u["phone"],
        "email_verified": bool(u["email_verified"]), "created_at": u["created_at"],
    }


@bp.get("/profile")
@login_required
def get_profile():
    s = load_settings(g.user["id"])
    return ok({
        "account": _account(g.user),
        "thresholds": s["thresholds"],
        "presets": SENSITIVITY_PRESETS,
        "ai_model": s["ai_model"],
        "available_ai_models": AVAILABLE_AI_MODELS,
        "privacy_controls": s["privacy_controls"],
        "retention_choices": RETENTION_CHOICES,
    })


@bp.put("/profile/account")
@login_required
def update_account():
    data = get_json()
    name = clean_name(data.get("name", g.user["name"]))
    phone = clean_phone(data.get("phone")) if "phone" in data else g.user["phone"]
    db = get_db()
    db.execute("UPDATE users SET name=?, phone=? WHERE id=?", (name, phone, g.user["id"]))
    db.commit()
    row = db.execute("SELECT * FROM users WHERE id=?", (g.user["id"],)).fetchone()
    return ok({"account": _account(row)})


@bp.post("/profile/change-password")
@login_required
@rate_limit(10, 900)
def change_password():
    data = get_json()
    current, new = data.get("current_password"), data.get("new_password")
    if not isinstance(current, str) or not check_password_hash(g.user["password_hash"], current):
        raise ApiError("INVALID_CREDENTIALS", "Your current password is incorrect.", 401,
                       {"current_password": "Incorrect password."})
    problems = password_problems(new, g.user["email"], g.user["name"])
    if problems:
        raise ApiError("WEAK_PASSWORD", "That password doesn't meet the rules.", 422, {"new_password": problems})
    if new == current:
        raise ApiError("SAME_PASSWORD", "Choose a password you haven't used here before.", 422,
                       {"new_password": ["Must differ from your current password"]})
    db = get_db()
    db.execute("UPDATE users SET password_hash=? WHERE id=?", (hash_password(new), g.user["id"]))
    # Changing the password signs out every other device.
    db.execute("UPDATE sessions SET revoked=1 WHERE user_id=? AND id<>?", (g.user["id"], g.session["id"]))
    db.commit()
    return ok({"changed": True})


@bp.put("/profile/thresholds")
@login_required
def update_thresholds():
    data = get_json()
    s = load_settings(g.user["id"])
    thresholds = dict(s["thresholds"])
    if "preset" in data:
        if data["preset"] not in SENSITIVITY_PRESETS:
            raise ApiError("INVALID_VALUE", "Preset must be relaxed, balanced or strict.", 422,
                           {"preset": "Use relaxed, balanced or strict."})
        thresholds = {k: SENSITIVITY_PRESETS[data["preset"]] for k in thresholds}
    for key, value in data.items():
        if key == "preset":
            continue
        if key not in thresholds:
            raise ApiError("UNKNOWN_FIELD", f"Unknown threshold: {key}.", 422)
        if isinstance(value, bool) or not isinstance(value, int) or not 5 <= value <= 95:
            raise ApiError("INVALID_VALUE", f"{key} must be a whole number from 5 to 95.", 422,
                           {key: "Use a whole number from 5 to 95."})
        thresholds[key] = value
    save_setting(g.user["id"], "thresholds", thresholds)
    return ok({"thresholds": thresholds})


@bp.put("/profile/ai-model")
@login_required
def update_ai_model():
    model = get_json().get("model")
    if model not in {m["id"] for m in AVAILABLE_AI_MODELS}:
        raise ApiError("INVALID_VALUE", "Choose one of the available AI models.", 422,
                       {"model": "Choose one of the available AI models."})
    save_setting(g.user["id"], "ai_model", model)
    return ok({"ai_model": model})


@bp.put("/profile/privacy-controls")
@login_required
def update_privacy_controls():
    data = dict(get_json())
    s = load_settings(g.user["id"])
    controls = dict(s["privacy_controls"])
    if "history_retention_days" in data:
        days = data.pop("history_retention_days")
        if isinstance(days, bool) or days not in RETENTION_CHOICES:
            raise ApiError("INVALID_VALUE", f"Retention must be one of {RETENTION_CHOICES} days.", 422,
                           {"history_retention_days": f"Choose one of {RETENTION_CHOICES}."})
        controls["history_retention_days"] = days
    if data:
        bool_defaults = {k: v for k, v in DEFAULT_PRIVACY_CONTROLS.items() if isinstance(v, bool)}
        controls.update(validate_bool_map(data, bool_defaults, "privacy controls"))
    save_setting(g.user["id"], "privacy_controls", controls)
    return ok({"privacy_controls": controls})


@bp.delete("/profile")
@login_required
@rate_limit(5, 900)
def delete_account():
    password = get_json().get("password")
    if not isinstance(password, str) or not check_password_hash(g.user["password_hash"], password):
        raise ApiError("INVALID_CREDENTIALS", "Your password is incorrect.", 401, {"password": "Incorrect password."})
    db = get_db()
    db.execute("DELETE FROM users WHERE id=?", (g.user["id"],))  # cascades to every table
    db.commit()
    return clear_session_cookie(ok({"deleted": True}))


# ------------------------------------------------------------- extension handover
@bp.get("/extension/config")
@login_required
def extension_config():
    """One call the browser extension makes after login to learn the user's settings."""
    s = load_settings(g.user["id"])
    if not s["privacy_controls"]["allow_extension_access"]:
        raise ApiError("EXTENSION_ACCESS_DISABLED",
                       "The user turned off extension access in Profile & Settings.", 403)
    trust = compute_trust(g.user)
    return ok({
        "user": {"id": g.user["id"], "name": g.user["name"], "email": g.user["email"]},
        "ai_model": s["ai_model"],
        "thresholds": s["thresholds"],
        "privacy_controls": s["privacy_controls"],
        "trust": {"score": trust["score"], "level": trust["level"]},
        "fetched_at": now(),
    })
