"""
CyberShield-AI Backend & Integration Test Suite
Verifies all REST API endpoints for Guidance, Settings, AI Assistant, and Research Papers.
"""

import sys
import os
import json
import unittest

sys.path.append(os.path.abspath(os.path.dirname(__file__)))
from app import app, DEFAULT_SETTINGS

class CyberShieldBackendTestCase(unittest.TestCase):
    
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    def test_01_health_check(self):
        response = self.app.get('/api/health')
        data = json.loads(response.data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data["status"], "online")
        self.assertEqual(data["app"], "CyberShield-AI")
        self.assertEqual(data["developer"], "Shreya")

    def test_02_get_guides(self):
        response = self.app.get('/api/guide')
        data = json.loads(response.data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data["status"], "success")
        self.assertGreaterEqual(data["count"], 6)

    def test_03_filter_guides_category(self):
        response = self.app.get('/api/guide?category=phishing')
        data = json.loads(response.data)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(all(g["category"] == "phishing" for g in data["guides"]))

    def test_04_ai_assistant_ask(self):
        payload = {"question": "How do I spot email spoofing phishing?"}
        response = self.app.post('/api/guide/ask', data=json.dumps(payload), content_type='application/json')
        data = json.loads(response.data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data["status"], "success")
        self.assertIn("Phishing Defense Recommendation", data["response"])

    def test_05_guide_progress(self):
        payload = {"guide_id": "phishing-defense", "completed": True}
        response = self.app.post('/api/guide/progress', data=json.dumps(payload), content_type='application/json')
        data = json.loads(response.data)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(data["progress"]["phishing-defense"])
        self.assertGreater(data["completedCount"], 0)

    def test_06_get_and_update_settings(self):
        # Get settings
        res1 = self.app.get('/api/settings')
        data1 = json.loads(res1.data)
        self.assertEqual(res1.status_code, 200)
        self.assertEqual(data1["status"], "success")
        
        # Update settings
        update_payload = {
            "security": {
                "threat_sensitivity": "paranoid",
                "deep_heuristics": True
            },
            "profile": {
                "name": "Shreya Lead Admin"
            }
        }
        res2 = self.app.post('/api/settings', data=json.dumps(update_payload), content_type='application/json')
        data2 = json.loads(res2.data)
        self.assertEqual(res2.status_code, 200)
        self.assertEqual(data2["settings"]["security"]["threat_sensitivity"], "paranoid")
        self.assertEqual(data2["settings"]["profile"]["name"], "Shreya Lead Admin")

    def test_07_reset_settings(self):
        res = self.app.post('/api/settings/reset')
        data = json.loads(res.data)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(data["settings"]["security"]["threat_sensitivity"], "high")

    def test_08_get_research_papers(self):
        res = self.app.get('/api/research-papers')
        data = json.loads(res.data)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(len(data["papers"]), 2)
        
        res_paper1 = self.app.get('/api/research-papers/paper-1')
        data_p1 = json.loads(res_paper1.data)
        self.assertEqual(res_paper1.status_code, 200)
        self.assertIn("Dynamic AI-Driven Cybersecurity Guidance", data_p1["content"])

if __name__ == '__main__':
    unittest.main()
