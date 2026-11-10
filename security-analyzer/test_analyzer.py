"""
Tests for CyberShield AI — Security Analyzer Service
Run:  python -m pytest test_analyzer.py -v
"""

import os
import json
import unittest
from unittest.mock import patch, MagicMock

from app import app, analyze_password


class BaseTestCase(unittest.TestCase):
    """Shared setup for all test classes."""

    def setUp(self):
        self.app = app
        self.app.config["TESTING"] = True
        self.app.config["RATELIMIT_ENABLED"] = False
        self.client = self.app.test_client()
        # Clear the leak cache between tests
        import app as app_module
        app_module._leak_cache.clear()


# ──────────────────────────────────────────────────────────────────────
#  PART A — Password endpoint tests
# ──────────────────────────────────────────────────────────────────────

class TestPasswordWeak(BaseTestCase):
    """Known weak password: 123456"""

    def test_weak_password_123456(self):
        resp = self.client.post(
            "/api/analyzer/password",
            json={"password": "123456"},
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["label"], "weak")
        self.assertLessEqual(data["score"], 15)
        self.assertIsInstance(data["issues"], list)
        self.assertTrue(len(data["issues"]) > 0)
        self.assertIsInstance(data["tips"], list)
        self.assertIsInstance(data["entropy_bits"], (int, float))
        self.assertIn("estimated_crack_time", data)
        self.assertIn("breached", data)
        self.assertIn("breach_count", data)


class TestPasswordMedium(BaseTestCase):
    """Medium-strength password."""

    def test_medium_password(self):
        resp = self.client.post(
            "/api/analyzer/password",
            json={"password": "Summer2024!"},
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn(data["label"], ("medium", "weak"))
        self.assertGreater(data["score"], 0)
        self.assertIsInstance(data["issues"], list)
        self.assertIsInstance(data["tips"], list)


class TestPasswordStrong(BaseTestCase):
    """Strong random password."""

    def test_strong_random_password(self):
        resp = self.client.post(
            "/api/analyzer/password",
            json={"password": "kG#9xL!mQ2$vR7pZ&nW4"},
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["label"], "strong")
        self.assertGreaterEqual(data["score"], 70)
        self.assertGreater(data["entropy_bits"], 60)


class TestPasswordEmpty(BaseTestCase):
    """Empty input → 400."""

    def test_empty_password(self):
        resp = self.client.post(
            "/api/analyzer/password",
            json={"password": ""},
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertIn("error", data)

    def test_missing_field(self):
        resp = self.client.post(
            "/api/analyzer/password",
            json={},
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)


class TestPasswordVeryLong(BaseTestCase):
    """Very long input → 413."""

    def test_very_long_password(self):
        resp = self.client.post(
            "/api/analyzer/password",
            json={"password": "A" * 2000},
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 413)
        data = resp.get_json()
        self.assertIn("error", data)


class TestPasswordPatterns(BaseTestCase):
    """Pattern detection: keyboard runs, sequences, leet-speak."""

    def test_qwerty_detected(self):
        data = analyze_password("qwerty12345")
        self.assertTrue(
            any("keyboard" in issue.lower() or "sequential" in issue.lower()
                for issue in data["issues"])
        )

    def test_leet_speak_detected(self):
        data = analyze_password("p@ssw0rd")
        self.assertEqual(data["label"], "weak")
        self.assertTrue(
            any("substitution" in i.lower() or "common" in i.lower()
                for i in data["issues"])
        )


class TestPasswordBreachCheck(BaseTestCase):
    """HIBP Pwned Passwords k-anonymity integration (kept from Part A)."""

    @patch("app.http_requests.get")
    def test_breached_password(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        # SHA-1 of "password" = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        mock_resp.text = (
            "1D2DA4053E34E76F6576ED1DA63174BD735:5\n"
            "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\n"
            "1F2B668E8AABEF1C59E9EC6F82E3F3CD786:2\n"
        )
        mock_get.return_value = mock_resp

        data = analyze_password("password")
        self.assertTrue(data["breached"])
        self.assertEqual(data["breach_count"], 3861493)
        self.assertEqual(data["label"], "weak")

    @patch("app.http_requests.get")
    def test_hibp_api_failure(self, mock_get):
        """When HIBP is unreachable, password analysis still works."""
        mock_get.side_effect = Exception("Network error")
        data = analyze_password("TestPassword123!")
        self.assertFalse(data["breached"])
        self.assertEqual(data["breach_count"], 0)


# ──────────────────────────────────────────────────────────────────────
#  PART B — Leak endpoint tests (XposedOrNot)
# ──────────────────────────────────────────────────────────────────────

class TestLeakBreachedEmail(BaseTestCase):
    """Email found in breaches (mocked XposedOrNot response)."""

    @patch("app.http_requests.get")
    def test_breached_email(self, mock_get):
        # First call: check-email → found
        check_resp = MagicMock()
        check_resp.status_code = 200
        check_resp.json.return_value = {
            "breaches": [["AdobeBreach", "LinkedInBreach"]]
        }

        # Second call: breach-analytics → details
        analytics_resp = MagicMock()
        analytics_resp.status_code = 200
        analytics_resp.json.return_value = {
            "ExposedBreaches": {
                "breaches_details": [
                    {
                        "breach": "AdobeBreach",
                        "xposed_date": "2013-10-04",
                        "xposed_data": "Email addresses, Passwords",
                    },
                    {
                        "breach": "LinkedInBreach",
                        "xposed_date": "2012-05-05",
                        "xposed_data": "Email addresses, Passwords",
                    },
                ]
            }
        }

        mock_get.side_effect = [check_resp, analytics_resp]

        resp = self.client.post(
            "/api/analyzer/leak",
            json={"type": "email", "value": "test@example.com"},
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["found"])
        self.assertEqual(data["breach_count"], 2)
        self.assertEqual(data["breaches"][0]["name"], "AdobeBreach")
        self.assertEqual(data["source"], "XposedOrNot")
        self.assertIn("checked_at", data)


class TestLeakCleanEmail(BaseTestCase):
    """Email not in any breach (mocked 404)."""

    @patch("app.http_requests.get")
    def test_clean_email(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_get.return_value = mock_resp

        resp = self.client.post(
            "/api/analyzer/leak",
            json={"type": "email", "value": "clean@example.com"},
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertFalse(data["found"])
        self.assertEqual(data["breach_count"], 0)
        self.assertIn("No known breaches found", data["advice"])
        self.assertEqual(data["source"], "XposedOrNot")


class TestLeakInvalidEmail(BaseTestCase):
    """Invalid email → 400."""

    def test_invalid_email(self):
        resp = self.client.post(
            "/api/analyzer/leak",
            json={"type": "email", "value": "not-an-email"},
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertIn("error", data)

    def test_empty_value(self):
        resp = self.client.post(
            "/api/analyzer/leak",
            json={"type": "email", "value": ""},
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)


class TestLeakAPIFailure(BaseTestCase):
    """External API failure → clear error message, no crash."""

    @patch("app.http_requests.get")
    def test_api_timeout(self, mock_get):
        import requests
        mock_get.side_effect = requests.Timeout("Connection timed out")

        resp = self.client.post(
            "/api/analyzer/leak",
            json={"type": "email", "value": "user@example.com"},
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertFalse(data["found"])
        self.assertIn("timed out", data["advice"])
        self.assertEqual(data["source"], "XposedOrNot")


class TestLeakRateLimit(BaseTestCase):
    """XposedOrNot 429 → clear rate-limit message."""

    @patch("app.http_requests.get")
    def test_rate_limited(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_get.return_value = mock_resp

        resp = self.client.post(
            "/api/analyzer/leak",
            json={"type": "email", "value": "user@example.com"},
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertFalse(data["found"])
        self.assertIn("Rate limit", data["advice"])


class TestLeakCaching(BaseTestCase):
    """Second call for same email uses cache, no extra API call."""

    @patch("app.http_requests.get")
    def test_cache_hit(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_get.return_value = mock_resp

        # First call
        self.client.post(
            "/api/analyzer/leak",
            json={"type": "email", "value": "cached@example.com"},
            content_type="application/json",
        )
        call_count_after_first = mock_get.call_count

        # Second call — should use cache
        resp = self.client.post(
            "/api/analyzer/leak",
            json={"type": "email", "value": "cached@example.com"},
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        # No additional HTTP calls made
        self.assertEqual(mock_get.call_count, call_count_after_first)


class TestLeakDomain(BaseTestCase):
    """Domain breach scan (mocked XposedOrNot /v1/breaches)."""

    @patch("app.http_requests.get")
    def test_domain_with_breaches(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {
                "breach": "AdobeBreach",
                "domain": "adobe.com",
                "xposed_date": "2013-10-04",
                "xposed_data": "Email addresses, Passwords, Usernames",
            },
            {
                "breach": "SomeOther",
                "domain": "other.com",
                "xposed_date": "2020-01-01",
                "xposed_data": "Emails",
            },
        ]
        mock_get.return_value = mock_resp

        resp = self.client.post(
            "/api/analyzer/leak",
            json={"type": "domain", "value": "adobe.com"},
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["found"])
        self.assertEqual(data["breach_count"], 1)  # only adobe.com matched
        self.assertEqual(data["source"], "XposedOrNot")

    def test_invalid_domain(self):
        resp = self.client.post(
            "/api/analyzer/leak",
            json={"type": "domain", "value": "not a domain!!"},
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)


class TestLeakInvalidType(BaseTestCase):
    """Invalid type field → 400."""

    def test_wrong_type(self):
        resp = self.client.post(
            "/api/analyzer/leak",
            json={"type": "phone", "value": "1234567890"},
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertIn("error", data)


# ──────────────────────────────────────────────────────────────────────
#  Health check
# ──────────────────────────────────────────────────────────────────────

class TestHealth(BaseTestCase):
    def test_health(self):
        resp = self.client.get("/api/analyzer/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "online")


if __name__ == "__main__":
    unittest.main()
