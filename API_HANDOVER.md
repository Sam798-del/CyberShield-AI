# CyberShield AI: API handover for the extension team

From: Kaveri (sign-up/login, Digital Identity, Profile/Settings)
Base URL while developing: `http://127.0.0.1:5000`

This document lists every endpoint the extension needs for **login**, **Digital Identity** and **Profile / Settings**: what to send, what comes back, and what can go wrong.

---

## 1. How the extension logs in (read this first)

1. Show a login form in the extension popup and call **`POST /api/auth/login`**.
2. The response contains `data.token`. Store it in `chrome.storage.session` (cleared when the browser closes), **not** in `localStorage` and not in a content script.
3. Send it on every call as a header: `Authorization: Bearer <token>`.
4. Right after login, call **`GET /api/extension/config`** to get the user's AI model, sensitivity thresholds and privacy controls.
5. To check "who is logged in?" at any time, call **`GET /api/auth/verify-token`**.
6. Tokens last 12 hours. On any `401` with code `TOKEN_EXPIRED`, `TOKEN_INVALID`, `SESSION_REVOKED` or `AUTH_REQUIRED`, delete the stored token and show the login form again.

**Make the calls from the extension's background service worker (or popup), not from a content script.** A content script runs inside the web page, so the browser treats its requests as coming from that page's origin (for example `https://bank.com`) and CORS blocks them. Content scripts should pass messages to the background worker with `chrome.runtime.sendMessage`.

The backend allows CORS only for `chrome-extension://` and `moz-extension://` origins. Before going live, set `ALLOWED_ORIGINS=chrome-extension://<your-extension-id>` in `.env`. Add `http://127.0.0.1:5000/*` (or your real domain) to `host_permissions` in `manifest.json`.

```js
// background.js (service worker)
const API = "http://127.0.0.1:5000/api";

async function login(email, password) {
  const res = await fetch(`${API}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  const json = await res.json();
  if (!json.ok) throw json.error;               // { code, message, fields? }
  await chrome.storage.session.set({ token: json.data.token });
  return json.data.user;
}

async function call(path, options = {}) {
  const { token } = await chrome.storage.session.get("token");
  const res = await fetch(`${API}${path}`, {
    ...options,
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}`, ...(options.headers || {}) },
  });
  const json = await res.json();
  if (!json.ok) {
    if (["TOKEN_EXPIRED", "TOKEN_INVALID", "SESSION_REVOKED", "AUTH_REQUIRED"].includes(json.error.code))
      await chrome.storage.session.remove("token");
    throw json.error;
  }
  return json.data;
}

// after login:
const config = await call("/extension/config");
```

> Sign-up needs an email code, so do it on the website (`/index.html`). The extension only needs **login**.

---

## 2. Response format (same everywhere)

Success:
```json
{ "ok": true, "data": { "...": "..." } }
```
Failure (HTTP status is 4xx/5xx):
```json
{ "ok": false, "error": { "code": "WEAK_PASSWORD", "message": "Readable message", "fields": { "password": ["One number"] } } }
```
`fields` is optional. Show `error.message` to the user and branch on `error.code` in code. All timestamps are Unix seconds (UTC).

---

## 3. Login and session endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/api/auth/login` | none | Log in, get token |
| GET | `/api/auth/verify-token` | Bearer | Who is logged in? |
| GET | `/api/auth/me` | Bearer | Current user + session expiry |
| POST | `/api/auth/logout` | Bearer | End this session |
| POST | `/api/auth/logout-all` | Bearer | End every session |
| GET | `/api/auth/sessions` | Bearer | List active sessions |
| DELETE | `/api/auth/sessions/<id>` | Bearer | End one session |

### POST `/api/auth/login`
Input:
```json
{ "email": "kaveri@example.com", "password": "Tr1cky!Pass#9" }
```
Output `200`:
```json
{ "ok": true, "data": {
  "token": "eyJhbGciOi...", "token_type": "Bearer", "expires_at": 1794603869,
  "user": { "id": 1, "name": "Kaveri Rao", "email": "kaveri@example.com", "email_verified": true, "phone": null, "created_at": 1794560000 }
} }
```
Errors: `401 INVALID_CREDENTIALS` (same message for wrong email or wrong password), `403 EMAIL_NOT_VERIFIED` (a new code was emailed; send the user to the website to finish), `423 ACCOUNT_LOCKED` (5 wrong passwords = 15 min lock), `429 RATE_LIMITED`.

### GET `/api/auth/verify-token`
Header: `Authorization: Bearer <token>`. No body.
Output `200`:
```json
{ "ok": true, "data": { "valid": true, "user_id": 1, "name": "Kaveri Rao", "email": "kaveri@example.com", "expires_at": 1794603869 } }
```
Invalid token → `401` with `TOKEN_EXPIRED`, `TOKEN_INVALID` or `SESSION_REVOKED`.

Other features (phishing, cyberbullying, and so on) use the same check on the server by adding `@login_required` to their routes; see README, "Protecting your own endpoints".

---

## 4. Extension config (settings the extension must obey)

### GET `/api/extension/config`
Auth: Bearer. No body.
```json
{ "ok": true, "data": {
  "user": { "id": 1, "name": "Kaveri Rao", "email": "kaveri@example.com" },
  "ai_model": "balanced",
  "thresholds": { "phishing": 60, "cyberbullying": 60, "password": 60, "leak": 60 },
  "privacy_controls": {
    "save_scan_history": true, "history_retention_days": 30, "share_anonymous_analytics": false,
    "mask_sensitive_text_in_logs": true, "allow_extension_access": true
  },
  "trust": { "score": 30, "level": "low" },
  "fetched_at": 1794560700
} }
```
How to use each value:

| Field | Meaning |
|---|---|
| `ai_model` | `fast`, `balanced` or `thorough`. Pass it to the analysis code. (The list lives in `services.py` → `AVAILABLE_AI_MODELS`; rename to your real models.) |
| `thresholds.*` | Integers 5-95. **Alert the user when a risk score is ≥ the threshold.** Lower number = more alerts. |
| `privacy_controls.save_scan_history` | If `false`, don't store scan results. |
| `privacy_controls.history_retention_days` | 7, 30, 90 or 365. Delete older history. |
| `privacy_controls.mask_sensitive_text_in_logs` | If `true`, mask passwords, emails and message text in incident logs. |
| `privacy_controls.share_anonymous_analytics` | If `false`, send no usage statistics. |
| `privacy_controls.allow_extension_access` | If `false`, this endpoint answers `403 EXTENSION_ACCESS_DISABLED`. Show "Turn on extension access in your CyberShield settings." |

Call it after login and again whenever the popup opens (settings can change on the website).

---

## 5. Digital Identity Hub (Who Am I Online?)

Digital Identity keeps ongoing track of the accounts, emails, and phone numbers the user owns online, assessing breach exposure, password health, and 2FA coverage.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/identity` | Bearer | Full digital identity overview: risk score, accounts, recommendations, 2FA stats, activity |
| POST | `/api/identity/accounts` | Bearer | Link a new account (checks breach intelligence automatically) |
| PUT | `/api/identity/accounts/<id>` | Bearer | Update account (e.g. toggle 2FA, change password status) |
| DELETE | `/api/identity/accounts/<id>` | Bearer | Remove linked account |
| POST | `/api/identity/accounts/<id>/recheck` | Bearer | Re-check breach exposure for single account |
| POST | `/api/identity/recheck-all` | Bearer | Re-check all linked accounts |
| POST | `/api/identity/seed-demo` | Bearer | Reset to sample accounts for viva/presentation |

### GET `/api/identity`
```json
{ "ok": true, "data": {
  "user": { "name": "Neeraja / Kaveri", "email": "neeraja@gmail.com", "email_verified": true },
  "identity_risk": {
    "score": 78,
    "level": "high",
    "summary": "2 accounts lack 2FA, 1 password reused across sites, 1 account exposed in a 2023 breach",
    "stats": { "total": 5, "safe": 1, "review": 2, "high": 2, "two_fa_enabled": 2, "two_fa_percentage": 40 }
  },
  "accounts": [
    {
      "id": 1,
      "account_name": "Instagram",
      "account_type": "social",
      "identifier": "neeraja@gmail.com",
      "password_health": "weak",
      "is_2fa_enabled": false,
      "breach_status": "exposed",
      "breach_badge": "Exposed 2023",
      "breach_details": { "source": "Instagram Scraped Credential Leak", "year": "2023", "data_classes": ["Passwords", "Email addresses"] },
      "last_checked_at": 1794560000,
      "risk_level": "high",
      "notes": "Main social profile"
    }
  ],
  "recommendations": [
    {
      "id": "breach_pw_1",
      "account_name": "Instagram",
      "priority": 1,
      "impact": "High Impact",
      "title": "Change the compromised password for Instagram",
      "detail": "Exposed in a 2023 breach and uses a weak or reused password.",
      "action": "fix_breach"
    },
    {
      "id": "2fa_1",
      "account_name": "Instagram",
      "priority": 2,
      "impact": "High Impact",
      "title": "Turn on 2FA for Instagram",
      "detail": "Adding two-factor authentication blocks 99% of automated credential attacks.",
      "action": "fix_2fa"
    }
  ],
  "activity_log": [
    { "id": 1, "action": "Added Instagram", "detail": "Identified breach exposure from 2023", "created_at": 1794560100 }
  ]
} }
```

### POST `/api/identity/accounts`
Input:
```json
{
  "account_name": "Instagram",
  "account_type": "social",
  "identifier": "neeraja@gmail.com",
  "password_health": "weak",
  "is_2fa_enabled": false
}
```
*Note: Never send plaintext passwords.* Pass only `password_health` (`strong`, `medium`, `weak`, `reused`, `sso`).


### POST `/api/identity/credentials`
Input:
```json
{ "doc_type": "pan", "holder_name": "Kaveri Rao", "number": "ABCPR1234F" }
```
`doc_type` is one of `aadhaar`, `pan`, `passport`, `driving_license`, `voter_id`. Spaces and hyphens in `number` are ignored.
Output `201`: `{ "credential": {...as above...}, "checks": [ { "check": "format", "passed": true, "detail": "..." } ], "trust": {...} }`.
Errors: `422 VERIFICATION_FAILED` (bad format or checksum), `422 INVALID_DOC_TYPE`, `409 DOCUMENT_IN_USE` (already linked to another account).
Adding a second document of the same type replaces the first. The full number is **never stored or returned**, only the last 4 digits.

> What "verified" means: the number passes the document's format rules and, for Aadhaar, the Verhoeff checksum. It does **not** prove a government issued it. That needs an official API such as DigiLocker. `identity_docs.validate_document` is the single place to plug one in.

### PUT `/api/identity/privacy-switches`
Input: any subset of the five switches, booleans only.
```json
{ "share_email": true }
```
Output: `{ "privacy_switches": { ...all five... } }`. `share_masked_numbers` is forced to `false` while `share_verified_documents` is `false`.

### POST `/api/identity/qr`
No body. Output `201`:
```json
{ "ok": true, "data": { "token": "Qk3...", "verify_url": "http://127.0.0.1:5000/verify.html?t=Qk3...", "expires_at": 1794560900, "ttl_seconds": 300 } }
```
Render `verify_url` as a QR image. A user has one live QR code at a time; creating a new one switches off the old one.

### GET `/api/identity/verify/<token>` (public, no login)
Returns only what the owner allows:
```json
{ "ok": true, "data": { "verified": true, "expires_at": 1794560900,
  "shared_fields": ["email_verified", "verified_documents_count", "name", "trust_score"],
  "shared": { "email_verified": true, "verified_documents_count": 1, "name": "Kaveri Rao", "trust_score": 65, "trust_level": "medium" } } }
```
Errors: `404 QR_INVALID`, `410 QR_REVOKED`, `410 QR_EXPIRED`.

---

## 6. Profile / Settings endpoints

| Method | Path | Body | Purpose |
|---|---|---|---|
| GET | `/api/profile` | none | Account + all settings |
| PUT | `/api/profile/account` | `{ "name", "phone" }` | Update name / phone |
| POST | `/api/profile/change-password` | `{ "current_password", "new_password" }` | Change password (logs out other devices) |
| PUT | `/api/profile/thresholds` | `{ "preset": "strict" }` or `{ "phishing": 40 }` | Sensitivity |
| PUT | `/api/profile/ai-model` | `{ "model": "thorough" }` | AI model |
| PUT | `/api/profile/privacy-controls` | any of the controls below | Privacy controls |
| DELETE | `/api/profile` | `{ "password": "..." }` | Delete account |

All require `Authorization: Bearer <token>`.

### GET `/api/profile`
```json
{ "ok": true, "data": {
  "account": { "name": "Kaveri Rao", "email": "kaveri@example.com", "phone": "+919876543210", "email_verified": true, "created_at": 1794560000 },
  "thresholds": { "phishing": 60, "cyberbullying": 60, "password": 60, "leak": 60 },
  "presets": { "relaxed": 80, "balanced": 60, "strict": 35 },
  "ai_model": "balanced",
  "available_ai_models": [ { "id": "fast", "label": "Fast", "description": "..." }, { "id": "balanced", "label": "Balanced", "description": "..." }, { "id": "thorough", "label": "Thorough", "description": "..." } ],
  "privacy_controls": { "save_scan_history": true, "history_retention_days": 30, "share_anonymous_analytics": false, "mask_sensitive_text_in_logs": true, "allow_extension_access": true },
  "retention_choices": [7, 30, 90, 365]
} }
```

Each `PUT` returns the saved value, for example `PUT /api/profile/thresholds` → `{ "thresholds": {...all four...} }`.
Validation errors are `422` (`INVALID_VALUE`, `UNKNOWN_FIELD`, `INVALID_PHONE`, `WEAK_PASSWORD`). `change-password` answers `401 INVALID_CREDENTIALS` if the current password is wrong.

---

## 7. Error codes

| Code | HTTP | Meaning |
|---|---|---|
| `AUTH_REQUIRED` | 401 | No token sent |
| `TOKEN_EXPIRED` | 401 | Token older than 12 h |
| `TOKEN_INVALID` | 401 | Token damaged or not ours |
| `SESSION_REVOKED` | 401 | User logged out / was logged out elsewhere |
| `INVALID_CREDENTIALS` | 401 | Wrong email/password (or wrong current password) |
| `EMAIL_NOT_VERIFIED` | 403 | Finish the email code on the website |
| `EXTENSION_ACCESS_DISABLED` | 403 | User switched extension access off |
| `ACCOUNT_LOCKED` | 423 | Too many wrong passwords |
| `RATE_LIMITED` | 429 | Too many requests |
| `VALIDATION` family (`INVALID_*`, `WEAK_PASSWORD`, `VERIFICATION_FAILED`, `UNKNOWN_FIELD`) | 422 | Bad input; see `error.fields` |
| `NOT_FOUND`, `QR_INVALID` | 404 | Doesn't exist |
| `QR_REVOKED`, `QR_EXPIRED` | 410 | QR no longer valid |
| `SERVER_ERROR` | 500 | Our bug; try again |
