import json
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from services import config
from services.ai_settings import test_connection as check_connection
from services.api import ai_assessment, public_ai_settings
from services.api import Handler


class AISettingsLocalTests(unittest.TestCase):
    def test_saved_key_is_used_but_never_returned_to_browser(self):
        with tempfile.TemporaryDirectory(dir=config.ROOT / "data") as folder:
            with patch.object(config, "UI_SETTINGS_FILE", Path(folder) / "settings.json"):
                settings, candidate = config.proposed_ai_settings(
                    "groq", "openai/gpt-oss-20b", "test-secret-key"
                )
                self.assertTrue(settings.ready)
                config.save_ai_settings(candidate)
                loaded = config.load_settings()
                self.assertEqual(loaded.api_key, "test-secret-key")
                self.assertEqual(loaded.provider, "groq")
                self.assertNotIn("test-secret-key", json.dumps(public_ai_settings(loaded)))
                unchanged, candidate = config.proposed_ai_settings("groq", "openai/gpt-oss-20b")
                self.assertEqual(unchanged.api_key, "test-secret-key")
                self.assertEqual(candidate["api_keys"]["groq"], "test-secret-key")

    def test_mock_connection_needs_no_key(self):
        with tempfile.TemporaryDirectory(dir=config.ROOT / "data") as folder:
            with patch.object(config, "UI_SETTINGS_FILE", Path(folder) / "settings.json"):
                settings, _ = config.proposed_ai_settings("mock", "mock-triage-model")
                self.assertTrue(check_connection(settings)["ok"])

    def test_mock_assessment_is_not_presented_as_live_ai(self):
        class MockService:
            settings = type("Settings", (), {"is_mock": True})()

        with patch("services.api.ai_service", return_value=MockService()):
            result = ai_assessment("INC-1")
        self.assertEqual(result["status"], "not_configured")
        self.assertIsNone(result["assessment"])

    def test_settings_http_save_does_not_return_key(self):
        with tempfile.TemporaryDirectory(dir=config.ROOT / "data") as folder:
            with patch.object(config, "UI_SETTINGS_FILE", Path(folder) / "settings.json"):
                body = json.dumps(
                    {
                        "provider": "groq",
                        "model": "openai/gpt-oss-20b",
                        "api_key": "test-secret-key",
                    }
                ).encode()

                class Request:
                    path = "/api/ai/settings"
                    headers = {
                        "Content-Type": "application/json",
                        "X-SOC-Desk-Settings": "1",
                        "Content-Length": str(len(body)),
                    }
                    rfile = io.BytesIO(body)
                    response = None

                    def allowed_origin(self):
                        return True

                    def require_session(self):
                        return {"username": "administrator", "csrf": "test"}

                    def require_csrf(self, session):
                        pass

                    def send_json(self, status, payload):
                        self.response = (status, payload)

                request = Request()
                Handler.do_POST(request)
                self.assertEqual(request.response[0], 200)
                self.assertNotIn("test-secret-key", json.dumps(request.response[1]))
                self.assertEqual(config.load_settings().api_key, "test-secret-key")


if __name__ == "__main__":
    unittest.main()
