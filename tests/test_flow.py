"""CyberShield AI — 34-Test Comprehensive Verification Suite."""
import os
import tempfile
import unittest

from identity_docs import validate_document, verhoeff_check_digit
from modules.phishing_engine import analyze_phishing
from modules.toxicity_engine import analyze_cyberbullying
from security import password_problems


def _make_app():
    from app import create_app
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    app = create_app({
        "TESTING": True,
        "DATABASE": db_path,
        "DEV_MODE": True,
        "RATELIMIT_ENABLED": False,
        "SMTP_HOST": "",          # force console-only OTP delivery
        "SMTP_USER": "",
        "SMTP_PASSWORD": "",
    })
    return app, db_fd, db_path


class CyberShieldComprehensiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app, cls.db_fd, cls.db_path = _make_app()
        cls._client = cls.app.test_client()
        # Pre-register + verify a user for login tests
        with cls.app.app_context():
            signup = cls._client.post("/api/auth/signup", json={
                "name": "Neeraja Admin",
                "email": "neeraja@example.com",
                "password": "Z7$vK4!xP9#mL2@",
            })
            otp = signup.get_json()["data"]["dev_otp"]
            cls._client.post("/api/auth/verify-otp", json={
                "email": "neeraja@example.com",
                "otp": otp,
                "purpose": "signup",
            })

    @classmethod
    def tearDownClass(cls):
        try:
            os.close(cls.db_fd)
            os.unlink(cls.db_path)
        except OSError:
            pass

    def setUp(self):
        self.client = self._client

    # --- 1-5: Core Health & Password Rules ---
    def test_01_healthz(self):
        res = self.client.get("/healthz")
        self.assertEqual(res.status_code, 200)

    def test_02_api_health(self):
        res = self.client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json()["status"], "online")
        self.assertEqual(res.get_json()["developer"], "Shreya")

    def test_03_weak_password_rejected(self):
        problems = password_problems("short", "Alice", "alice@test.com")
        self.assertTrue(len(problems) > 0)

    def test_04_password_contains_name_rejected(self):
        problems = password_problems("AlicePass123!@#", "Alice", "alice@test.com")
        self.assertTrue(any("name" in p.lower() for p in problems))

    def test_05_strong_password_accepted(self):
        problems = password_problems("K9#mQ2$vL8!zW5@", "Alice", "alice@test.com")
        self.assertEqual(len(problems), 0)

    # --- 6-10: Auth & Registration Flow ---
    def test_06_signup_validation_error(self):
        res = self.client.post("/api/auth/signup", json={"name": "", "email": "bad", "password": "123"})
        self.assertIn(res.status_code, (422, 400))

    def test_07_signup_new_user(self):
        res = self.client.post("/api/auth/signup", json={
            "name": "Kaveri Lead",
            "email": "kaveri_test@example.com",
            "password": "K9#mQ2$vL8!zW5@",
        })
        self.assertEqual(res.status_code, 201)
        data = res.get_json()["data"]
        self.assertTrue(data["otp_required"])
        self.assertIn("dev_otp", data)

    def test_08_verify_otp_wrong_code(self):
        res = self.client.post("/api/auth/verify-otp", json={
            "email": "kaveri_test@example.com",
            "otp": "000000",
            "purpose": "signup",
        })
        self.assertIn(res.status_code, (400, 422))

    def test_09_verify_otp_bad_format(self):
        res = self.client.post("/api/auth/verify-otp", json={
            "email": "kaveri_test@example.com",
            "otp": "abc",
        })
        self.assertEqual(res.status_code, 422)

    def test_10_login_wrong_password(self):
        res = self.client.post("/api/auth/login", json={
            "email": "neeraja@example.com",
            "password": "WrongPassword123!@#",
        })
        self.assertEqual(res.status_code, 401)

    # --- 11-15: Login, Session & Extension Config ---
    def test_11_login_success(self):
        res = self.client.post("/api/auth/login", json={
            "email": "neeraja@example.com",
            "password": "Z7$vK4!xP9#mL2@",
        })
        self.assertEqual(res.status_code, 200)
        self.assertIn("token", res.get_json()["data"])

    def test_12_verify_token_endpoint(self):
        login_res = self.client.post("/api/auth/login", json={
            "email": "neeraja@example.com",
            "password": "Z7$vK4!xP9#mL2@",
        })
        token = login_res.get_json()["data"]["token"]
        res = self.client.get("/api/auth/verify-token", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json()["data"]["email"], "neeraja@example.com")

    def test_13_extension_config(self):
        login_res = self.client.post("/api/auth/login", json={
            "email": "neeraja@example.com",
            "password": "Z7$vK4!xP9#mL2@",
        })
        token = login_res.get_json()["data"]["token"]
        res = self.client.get("/api/extension/config", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(res.status_code, 200)
        self.assertIn("thresholds", res.get_json()["data"])

    def test_14_logout_revokes_token(self):
        login_res = self.client.post("/api/auth/login", json={
            "email": "neeraja@example.com",
            "password": "Z7$vK4!xP9#mL2@",
        })
        token = login_res.get_json()["data"]["token"]
        self.client.post("/api/auth/logout", headers={"Authorization": f"Bearer {token}"})
        verify_res = self.client.get("/api/auth/verify-token", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(verify_res.status_code, 401)

    def test_15_identity_overview(self):
        login_res = self.client.post("/api/auth/login", json={
            "email": "neeraja@example.com",
            "password": "Z7$vK4!xP9#mL2@",
        })
        token = login_res.get_json()["data"]["token"]
        res = self.client.get("/api/identity", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(res.status_code, 200)
        self.assertIn("trust", res.get_json()["data"])

    # --- 16-20: Document Validation (Aadhaar, PAN, Passport) ---
    def test_16_aadhaar_valid_checksum(self):
        base = "36759834231"
        cd = verhoeff_check_digit(base)
        valid_num = base + str(cd)
        checks = validate_document("aadhaar", valid_num, "Test User")
        self.assertTrue(all(c["passed"] for c in checks))

    def test_17_aadhaar_invalid_letters(self):
        checks = validate_document("aadhaar", "12345678901A", "Test User")
        self.assertFalse(all(c["passed"] for c in checks))

    def test_18_pan_valid_format(self):
        checks = validate_document("pan", "ABCPE1234F", "Evans Test")
        self.assertTrue(all(c["passed"] for c in checks))

    def test_19_pan_invalid_length(self):
        checks = validate_document("pan", "ABC123F", "Test")
        self.assertFalse(all(c["passed"] for c in checks))

    def test_20_passport_valid_format(self):
        checks = validate_document("passport", "A1234567", "Test User")
        self.assertTrue(all(c["passed"] for c in checks))

    # --- 21-25: Phishing Detection Engine ---
    def test_21_phishing_http_risky_tld(self):
        res = analyze_phishing("http://secure-update-account.xyz/login")
        self.assertGreater(res["risk_score"], 40)

    def test_22_phishing_lookalike_spoof(self):
        res = analyze_phishing("https://paypa1-verify-account.com/auth")
        self.assertGreaterEqual(res["risk_score"], 45)

    def test_23_phishing_clean_url(self):
        res = analyze_phishing("https://www.google.com")
        self.assertLess(res["risk_score"], 30)

    def test_24_phishing_api_endpoint(self):
        res = self.client.post("/api/detect/phishing", json={"target": "http://paypa1-alert.top"})
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.get_json()["is_phishing"])

    def test_25_phishing_empty_target(self):
        res = self.client.post("/api/detect/phishing", json={"target": ""})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json()["risk_score"], 0)

    # --- 26-29: Cyberbullying NLP Engine ---
    def test_26_threat_detection(self):
        res = analyze_cyberbullying("I will find you and hurt you tomorrow")
        self.assertGreaterEqual(res["toxicity_score"], 50)

    def test_27_harassment_detection(self):
        res = analyze_cyberbullying("nobody likes you you loser delete your account")
        self.assertGreaterEqual(res["toxicity_score"], 35)

    def test_28_safe_text(self):
        res = analyze_cyberbullying("Great presentation on cybersecurity today!")
        self.assertLess(res["toxicity_score"], 30)

    def test_29_cyberbullying_api_endpoint(self):
        res = self.client.post("/api/detect/cyberbullying", json={"text": "I will destroy you"})
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.get_json()["is_toxic"])

    # --- 30-34: Guidance, Settings, Analyzer & Telemetry ---
    def test_30_guidance_list(self):
        res = self.client.get("/api/guide")
        self.assertEqual(res.status_code, 200)
        self.assertGreaterEqual(res.get_json()["count"], 6)

    def test_31_guidance_ask_ai(self):
        res = self.client.post("/api/guide/ask", json={"question": "phishing defense advice"})
        self.assertEqual(res.status_code, 200)
        self.assertIn("Phishing Defense Recommendation", res.get_json()["response"])

    def test_32_settings_get_and_update(self):
        res1 = self.client.get("/api/settings")
        self.assertEqual(res1.status_code, 200)
        res2 = self.client.post("/api/settings", json={"security": {"threat_sensitivity": "paranoid"}})
        self.assertEqual(res2.get_json()["settings"]["security"]["threat_sensitivity"], "paranoid")

    def test_33_analyzer_endpoints(self):
        res = self.client.get("/api/analyzer/health")
        self.assertEqual(res.status_code, 200)
        res_pw = self.client.post("/api/analyzer/password", json={"password": "TestPass123!@#"})
        self.assertEqual(res_pw.status_code, 200)
        self.assertIn("score", res_pw.get_json())

    def test_34_realtime_telemetry(self):
        self.client.post("/api/telemetry/incident", json={
            "title": "Malicious Phishing Vector Blocked",
            "module": "Phishing Detection",
            "severity": "Critical",
            "target": "evil-portal.xyz",
        })
        t_res = self.client.get("/api/telemetry")
        self.assertEqual(t_res.status_code, 200)
        self.assertTrue(len(t_res.get_json()["incidents"]) > 0)


if __name__ == "__main__":
    unittest.main()
