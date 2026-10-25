import tempfile
import io
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from services import auth
from services.api import Handler


class LocalAuthTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1] / "data")
        self.patch = patch.object(auth, "AUTH_FILE", Path(self.folder.name) / "account.json")
        self.patch.start()
        auth._sessions.clear()
        auth._failures.clear()

    def tearDown(self):
        self.patch.stop()
        auth._sessions.clear()
        auth._failures.clear()
        self.folder.cleanup()

    def test_change_requires_current_password_and_revokes_sessions(self):
        first, session = auth.login("administrator", "Demo@1234")
        second, _ = auth.login("administrator", "Demo@1234")
        self.assertIsNotNone(auth.current_session(f"soc_session={first}"))
        with self.assertRaises(auth.AuthError):
            auth.change_password(session, "wrong", "a new unique passphrase")
        self.assertIsNotNone(auth.current_session(f"soc_session={second}"))
        auth.change_password(session, "Demo@1234", "a new unique passphrase")
        self.assertIsNone(auth.current_session(f"soc_session={first}"))
        self.assertIsNone(auth.current_session(f"soc_session={second}"))
        with self.assertRaises(auth.AuthError):
            auth.login("administrator", "Demo@1234")
        auth.login("administrator", "a new unique passphrase")
        self.assertNotIn("a new unique passphrase", auth.AUTH_FILE.read_text(encoding="utf-8"))

    def test_policy_and_throttle(self):
        self.assertIsNotNone(auth.password_error("short"))
        self.assertIsNotNone(auth.password_error("passwordpassword"))
        self.assertIsNone(auth.password_error("安全口令 可以包含空格和不同语言的字符"))
        for attempt in range(5):
            with self.assertRaises(auth.AuthError) as error:
                auth.login("administrator", "wrong")
            self.assertEqual(error.exception.status, 429 if attempt == 4 else 401)
        with self.assertRaises(auth.AuthError) as error:
            auth.login("administrator", "Demo@1234")
        self.assertEqual(error.exception.status, 429)

    def test_http_login_change_and_unauthenticated_api(self):
        class Request:
            allowed_origin = Handler.allowed_origin
            request_body = Handler.request_body
            require_session = Handler.require_session
            require_csrf = Handler.require_csrf

            def __init__(self, path, payload=None, headers=None):
                body = json.dumps(payload or {}).encode()
                self.path = path
                self.rfile = io.BytesIO(body)
                self.headers = {
                    "Content-Type": "application/json",
                    "Content-Length": str(len(body)),
                    **(headers or {}),
                }
                self.response = None

            def send_json(self, status, payload, extra_headers=None):
                self.response = (status, payload, extra_headers or {})

        denied = Request("/api/cases/queue")
        Handler.do_GET(denied)
        self.assertEqual(denied.response[0], 401)
        sign_in = Request(
            "/api/auth/login",
            {"username": "administrator", "password": "Demo@1234"},
            {"X-SOC-Desk-Auth": "1"},
        )
        Handler.do_POST(sign_in)
        self.assertEqual(sign_in.response[0], 200)
        cookie = sign_in.response[2]["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        missing_csrf = Request(
            "/api/auth/change-password",
            {"current_password": "Demo@1234", "new_password": "a fresh unique passphrase"},
            {"Cookie": cookie},
        )
        Handler.do_POST(missing_csrf)
        self.assertEqual(missing_csrf.response[0], 403)
        change = Request(
            "/api/auth/change-password",
            {"current_password": "Demo@1234", "new_password": "a fresh unique passphrase"},
            {"Cookie": cookie, "X-CSRF-Token": sign_in.response[1]["csrf_token"]},
        )
        Handler.do_POST(change)
        self.assertEqual(change.response[0], 200)
        old_session = Request("/api/auth/session", headers={"Cookie": cookie})
        Handler.do_GET(old_session)
        self.assertFalse(old_session.response[1]["authenticated"])


if __name__ == "__main__":
    unittest.main()
