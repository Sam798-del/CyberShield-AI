# CyberShield AI — AI-Powered Cybersecurity & Threat Protection Suite

[![Live Demo](https://img.shields.io/badge/Live%20Demo-Render-38bdf8?style=for-the-badge&logo=render)](https://cybershield-ai-fdd1.onrender.com)
[![Tests Passing](https://img.shields.io/badge/Tests-34%20Passing-10b981?style=for-the-badge)](https://cybershield-ai-fdd1.onrender.com)

> 🌐 **Live Production Deployment**: **[https://cybershield-ai-fdd1.onrender.com](https://cybershield-ai-fdd1.onrender.com)**

---

## Run it locally

```bash
python -m venv venv
venv\Scripts\activate          # Windows   (Mac/Linux: source venv/bin/activate)
pip install -r requirements.txt
copy .env.example .env         # Mac/Linux: cp .env.example .env
```
Then open `.env` and set up email (next section), and start the app:
```bash
python app.py
```
Open http://127.0.0.1:5000

Run the tests: `python -m unittest tests.test_flow` (34 tests).

## Email: how every user gets their own code

Nothing is pre-set. Every person creates their own account, and the server emails **a new random 6-digit code to the address they typed**. A code works only for that one account, expires in 10 minutes and is stored only as a hash.

The server needs one email account to send from. Gmail is the easiest:
1. Turn on 2-Step Verification on the Gmail account you'll send from.
2. Google Account → Security → **App passwords** → create one (you get 16 characters).
3. In `.env` fill in:
   ```
   DEV_MODE=0
   SMTP_HOST=smtp.gmail.com
   SMTP_PORT=587
   SMTP_USER=youraddress@gmail.com
   SMTP_PASSWORD=the-16-character-app-password
   MAIL_FROM=CyberShield AI <youraddress@gmail.com>
   ```
4. Restart `python app.py`. Sign up with any email you can open and check the inbox (and spam folder).

If email isn't set up, the sign-up screen says it couldn't send the email. It never shows or reveals the code.

**Testing alone on your laptop without email:** set `DEV_MODE=1`. The code is then printed in the terminal and shown on the sign-up screen. This lets anyone skip email verification, so never leave it on for real users.

## Live Deployment & Cloud Hosting

The platform is deployed live on **Render Cloud**:
- **Live URL**: [https://cybershield-ai-fdd1.onrender.com](https://cybershield-ai-fdd1.onrender.com)
- **Start Command**: `gunicorn app:app` (or `python -m gunicorn app:app --bind 0.0.0.0:$PORT`)
- **Environment**: Python 3 with `gunicorn`, real-time Gmail SMTP for OTP authentication, and SQLite persistent storage.

## Letting other people use it

GitHub stores the code but doesn't run it, so other people can't use `http://127.0.0.1:5000` (that address only exists on your own computer). To let real users sign up, deploy it to a Python host (for example Render or PythonAnywhere): upload the repo, set the same values from `.env` as the host's environment variables, set `COOKIE_SECURE=1` (hosts give you HTTPS), and start it with `gunicorn "app:create_app()"`. Add `gunicorn` to `requirements.txt` for that. SQLite stores data in a file, so choose a host with a persistent disk.

## What's where

| File | What it does |
|---|---|
| `app.py` | Starts the app, CORS for the extension, security headers, JSON errors |
| `security.py` | Password rules, OTP, email sending, sessions/tokens, rate limiting |
| `routes_auth.py` | Sign-up, OTP, login, logout, token check, device list |
| `routes_identity.py` | Documents, privacy switches, QR verification, trust score |
| `routes_profile.py` | Account, password, sensitivity, AI model, privacy controls, `/api/extension/config` |
| `identity_docs.py` | Aadhaar / PAN / passport / licence / voter ID checks |
| `services.py` | Settings defaults + the trust-score formula |
| `static/` | The website: `index.html` (login), `app.html` (identity + settings), `verify.html` (QR page) |
| `API_HANDOVER.md` | **Give this to the extension team** |

## How the required items are met

- **Password rules:** 8-64 characters, upper + lower case, number, special character, no spaces, not a common password, can't contain your name or email name. Checked live in the browser and again on the server. Stored with scrypt and a per-password salt.
- **OTP email verification:** a fresh random 6-digit code is emailed to each user's own address, stored only as a keyed hash, tied to that one account, valid 10 minutes, max 5 wrong tries, resend every 30 s, max 6 per hour.
- **Secure sessions:** signed token (12 h) that is also tracked server-side, so logout really ends it. Website uses an `HttpOnly`, `SameSite=Lax` cookie (JavaScript can't read it) plus a CSRF header. Account locks for 15 min after 5 wrong passwords. Changing the password logs out other devices. Users can see and end their sessions.
- **Login token for the extension:** `POST /api/auth/login` returns it. `GET /api/auth/verify-token` tells any feature who is logged in.
- **Digital Identity:** document verification, privacy switches that control what a QR scan reveals, a time-limited QR code, and a trust score (0-100) calculated from real account data with a visible breakdown.
- **Profile / Settings:** account details, change password, sensitivity thresholds (presets + per-module), AI model choice, privacy controls, active sessions, delete account.

## Protecting your own endpoints (Shreya, Neeraja)

```python
from flask import Blueprint, g
from responses import ok
from security import login_required
from services import load_settings

bp = Blueprint("phishing", __name__, url_prefix="/api/phishing")

@bp.post("/check")
@login_required                      # rejects requests without a valid token
def check():
    user_id = g.user["id"]           # who is logged in
    s = load_settings(user_id)       # the user's thresholds, AI model, privacy controls
    limit = s["thresholds"]["phishing"]   # alert when risk score >= limit
    ...
    return ok({"risk": 72, "alert": 72 >= limit})
```
Register it in `create_app` in `app.py` next to the other blueprints.

## Things to know before the demo or going live

- **"Verified" document = valid format and checksum**, not confirmed with the government. Say this in your viva or report. A real issuer check (for example DigiLocker) would replace `validate_document`.
- **AI models** (`fast`, `balanced`, `thorough`) are placeholders. Rename them in `services.py` → `AVAILABLE_AI_MODELS` to the models your team actually uses.
- **The QR image** is drawn in the browser by a small library from cdnjs, so the page needs internet. If it can't load, the page shows the link instead.
- On a real server: serve over HTTPS and set `COOKIE_SECURE=1`, set `ALLOWED_ORIGINS` to your extension ID, and run with a production server (for example `gunicorn app:create_app()`) rather than `python app.py`. The rate limiter keeps counts in memory, so use one worker or move it to Redis.
- Not included (not in the assignment): forgot-password and email change. Both can reuse `issue_otp` / `check_otp` in `security.py` with a new `purpose`.
