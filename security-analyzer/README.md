# CyberShield AI — Security Analyzer Service

Standalone backend microservice that provides **password strength analysis**
and **email/domain data-breach scanning** for the CyberShield AI project.

> This service is independent. It has its own folder, its own dependencies,
> and runs on its own URL. It does not import or depend on any other
> teammate's code.

---

## Quick Start

```bash
# 1. Navigate to the service folder
cd security-analyzer

# 2. Create a virtual environment (recommended)
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS / Linux

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the server (default port 5050)
python app.py
```

The service starts at **http://localhost:5050**.
No API keys are required! The service uses:
- **Have I Been Pwned Pwned Passwords** k-anonymity (free, no key) for password breach checks.
- **XposedOrNot** API (free, no key) for email and domain leak scanning.

---

## Environment Variables

| Variable        | Required? | Default | Description |
|-----------------|-----------|---------|-------------|
| `ANALYZER_PORT` | No | `5050` | Port the HTTP server listens on. |

---

## Endpoints

### Health Check

```http
GET /api/analyzer/health
```

Response:
```json
{
  "status": "online",
  "service": "Security Analyzer",
  "project": "CyberShield AI"
}
```

---

### POST `/api/analyzer/password`

Analyze a password's strength, entropy, patterns, and breach status.

**Request:**
```json
{
  "password": "Neeraja@2007"
}
```

**Response (200):**
```json
{
  "score": 42,
  "label": "medium",
  "entropy_bits": 52.44,
  "breached": false,
  "breach_count": 0,
  "issues": [
    "Contains sequential characters (e.g. 1234, abcd)"
  ],
  "tips": [
    "Avoid alphabetical or numerical sequences"
  ],
  "estimated_crack_time": "about 14 days"
}
```

---

### POST `/api/analyzer/leak`

Scan an email address or domain for known data breaches using the free **XposedOrNot** API.

#### Email scan

**Request:**
```json
{
  "type": "email",
  "value": "user@example.com"
}
```

**Response (200) — breaches found:**
```json
{
  "found": true,
  "breach_count": 2,
  "breaches": [
    {
      "name": "AdobeBreach",
      "date": "2013-10-04",
      "data_exposed": ["Email addresses", "Passwords"]
    },
    {
      "name": "LinkedInBreach",
      "date": "2012-05-05",
      "data_exposed": ["Email addresses", "Passwords"]
    }
  ],
  "advice": "Your email was found in known breaches. Change passwords on the affected services and enable 2FA.",
  "source": "XposedOrNot",
  "checked_at": "2026-11-08T00:50:00+00:00"
}
```

**Response (200) — clean email:**
```json
{
  "found": false,
  "breach_count": 0,
  "breaches": [],
  "advice": "No known breaches found in XposedOrNot.",
  "source": "XposedOrNot",
  "checked_at": "2026-11-08T00:50:00+00:00"
}
```

#### Domain scan

**Request:**
```json
{
  "type": "domain",
  "value": "adobe.com"
}
```

**Response (200):**
```json
{
  "found": true,
  "breach_count": 1,
  "breaches": [
    {
      "name": "Adobe",
      "date": "2013-10-04",
      "data_exposed": ["Email addresses", "Passwords", "Usernames"]
    }
  ],
  "advice": "Domain adobe.com is linked to known breaches. Review affected accounts and rotate credentials.",
  "source": "XposedOrNot",
  "checked_at": "2026-11-08T00:50:00+00:00"
}
```

---

## Rate Limits & Caching

1. **XposedOrNot Rate Limits**: Free tier allows ~2 requests per second and ~100 per day per IP.
   - The backend automatically caches leak scan results in memory for 5 minutes (TTL 300s).
   - If XposedOrNot returns HTTP 429, the endpoint returns a clear error message: `"Rate limit reached on XposedOrNot. Please try again later."`.
2. **Local Flask Rate Limits**:
   - `POST /api/analyzer/password`: 30 requests per minute
   - `POST /api/analyzer/leak`: 15 requests per minute
   - Global: 200 requests per hour

---

## Authorization (Optional)

If a request includes an `Authorization: Bearer <token>` header, the service
hashes the token and stores it as a user identifier alongside each scan
record in `analyzer.db`. Requests **without** a token still work — they just aren't saved
to the scan log.

---

## Running Tests

```bash
cd security-analyzer
python -m pytest test_analyzer.py -v
```

All 21 test cases cover:
- ✅ Known weak password (`123456`)
- ✅ Medium-strength password
- ✅ Strong random password
- ✅ Empty input
- ✅ Very long input
- ✅ Breached email (XposedOrNot mock)
- ✅ Clean email (XposedOrNot 404 mock)
- ✅ Invalid email format
- ✅ External API timeout
- ✅ XposedOrNot rate limit response
- ✅ In-memory cache hit (no redundant HTTP request)
- ✅ Domain breach scan
- ✅ Invalid type field
- ✅ Leet-speak and keyboard-run pattern detection
- ✅ HIBP Pwned Passwords k-anonymity check
- ✅ Health check
