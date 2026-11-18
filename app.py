"""CyberShield AI - accounts, Digital Identity, Guidance, Detection & Profile service.

Run:  python app.py      then open http://127.0.0.1:5000
"""
import os
import secrets
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory
from werkzeug.exceptions import HTTPException

import db as database
from responses import ApiError, error_response
from routes_modules import DEFAULT_SETTINGS, bp as modules_bp

BASE_DIR = Path(__file__).resolve().parent


def load_env_file(path):
    """Tiny .env reader so no extra package is needed."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip())


def env_bool(name, default="0"):
    return os.environ.get(name, default).strip().lower() in {"1", "true", "yes", "on"}


def load_secret_key(instance_path):
    if os.environ.get("SECRET_KEY"):
        return os.environ["SECRET_KEY"]
    key_file = Path(instance_path) / "secret.key"
    if not key_file.exists():
        key_file.write_text(secrets.token_hex(32))
        try:
            key_file.chmod(0o600)
        except OSError:
            pass
    return key_file.read_text().strip()


def create_app(test_config=None):
    load_env_file(BASE_DIR / ".env")
    app = Flask(__name__, static_folder="frontend", static_url_path="", instance_relative_config=True)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    app.config.update(
        SECRET_KEY=load_secret_key(app.instance_path),
        DATABASE=str(Path(app.instance_path) / "cybershield.db"),
        DEV_MODE=env_bool("DEV_MODE", "1"),
        COOKIE_SECURE=env_bool("COOKIE_SECURE", "0"),
        SESSION_HOURS=12,
        OTP_TTL_SECONDS=600,
        OTP_RESEND_SECONDS=30,
        OTP_MAX_PER_HOUR=6,
        OTP_MAX_ATTEMPTS=5,
        MAX_FAILED_LOGINS=5,
        LOCKOUT_SECONDS=900,
        QR_TTL_SECONDS=300,
        RATELIMIT_ENABLED=True,
        SMTP_HOST=os.environ.get("SMTP_HOST", ""),
        SMTP_PORT=int(os.environ.get("SMTP_PORT", "587") or 587),
        SMTP_USER=os.environ.get("SMTP_USER", ""),
        SMTP_PASSWORD=os.environ.get("SMTP_PASSWORD", ""),
        SMTP_SSL=env_bool("SMTP_SSL", "0"),
        MAIL_FROM=os.environ.get("MAIL_FROM", "CyberShield AI <no-reply@localhost>"),
        ALLOWED_ORIGINS=[o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "").split(",") if o.strip()],
        MAX_CONTENT_LENGTH=64 * 1024,
    )
    if test_config:
        app.config.update(test_config)

    if app.config["DEV_MODE"]:
        print("\n!! DEV_MODE is ON: verification codes are shown on screen. Turn it off (DEV_MODE=0) for real users.\n")
    elif not app.config["SMTP_HOST"] and not app.config.get("TESTING"):
        print("\n!! Email is not set up: nobody can receive a verification code. Fill in SMTP_* in .env (see README).\n")

    database.init_db(app)
    app.teardown_appcontext(database.close_db)

    from routes_auth import bp as auth_bp
    from routes_identity import bp as identity_bp
    from routes_profile import bp as profile_bp

    # Register blueprints
    for blueprint in (auth_bp, identity_bp, profile_bp):
        app.register_blueprint(blueprint)

    app.register_blueprint(modules_bp, url_prefix="/api")

    # ------------------------------------------------------------ pages & static routing
    @app.get("/")
    def home():
        return send_from_directory(app.static_folder, "index.html")

    @app.get("/<page>.html")
    def serve_html_page(page):
        # 1. Check root of frontend
        root_path = Path(app.static_folder) / f"{page}.html"
        if root_path.exists():
            return send_from_directory(app.static_folder, f"{page}.html")
        # 2. Check frontend/pages/
        pages_path = Path(app.static_folder) / "pages" / f"{page}.html"
        if pages_path.exists():
            return send_from_directory(Path(app.static_folder) / "pages", f"{page}.html")
        return send_from_directory(app.static_folder, "index.html")

    @app.get("/pages/<path:filename>")
    def serve_pages_folder(filename):
        return send_from_directory(Path(app.static_folder) / "pages", filename)

    @app.get("/manifest.json")
    def serve_manifest():
        return send_from_directory('frontend', 'manifest.json', mimetype='application/manifest+json')

    @app.get("/healthz")
    def healthz():
        return jsonify({"ok": True})

    # ------------------------------------------------------------- CORS
    def origin_allowed(origin):
        allowed = app.config["ALLOWED_ORIGINS"]
        if allowed:
            return origin in allowed
        return origin.startswith(("chrome-extension://", "moz-extension://", "http://localhost", "http://127.0.0.1"))

    @app.before_request
    def preflight():
        if request.method == "OPTIONS" and request.path.startswith("/api/"):
            return "", 204

    @app.after_request
    def add_headers(resp):
        origin = request.headers.get("Origin")
        if origin and request.path.startswith("/api/") and origin_allowed(origin):
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
            resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
            resp.headers["Access-Control-Max-Age"] = "600"
            resp.headers.add("Vary", "Origin")

        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self' 'unsafe-inline' 'unsafe-eval' https: http: data: blob:; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; style-src-attr 'unsafe-inline'; "
            "font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: https: blob:; connect-src 'self' http://localhost:* http://127.0.0.1:* https: ws: wss:; "
            "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        )
        if request.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    # ----------------------------------------------------------- errors
    @app.errorhandler(ApiError)
    def handle_api_error(err):
        return error_response(err.code, err.message, err.status, err.fields)

    @app.errorhandler(HTTPException)
    def handle_http_error(err):
        if request.path.startswith("/api/"):
            code = {404: "NOT_FOUND", 405: "METHOD_NOT_ALLOWED", 413: "TOO_LARGE"}.get(err.code, "HTTP_ERROR")
            return error_response(code, err.description, err.code)
        return err

    @app.errorhandler(Exception)
    def handle_unexpected(err):
        app.logger.exception("Unhandled error")
        return error_response("SERVER_ERROR", "Something went wrong on our side. Try again.", 500)

    return app


# Export app instance at module level so test_backend.py and desktop/main.py can import it
app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
