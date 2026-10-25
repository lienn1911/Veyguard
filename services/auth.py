"""Local single-user authentication for the SOC Desk demo API.

Adapted to the standard-library HTTP server from DWG File Identifier's
password policy, failure limiter and password-version invalidation design.
"""

import hashlib
import hmac
import json
import math
import os
import secrets
import tempfile
import time
from collections import OrderedDict
from http.cookies import SimpleCookie
from pathlib import Path
from threading import RLock

AUTH_FILE = Path(__file__).resolve().parents[1] / "data" / "auth" / "account.json"
USERNAME = "administrator"
SESSION_SECONDS = 8 * 60 * 60
_lock = RLock()
_sessions = {}
_failures = OrderedDict()
_dummy = None

COMMON_PASSWORDS = {
    "password",
    "password123",
    "password123456789",
    "passwordpassword",
    "passwordpassword1",
    "passwordpassword!",
    "123456789012345",
    "1234567890123456",
    "qwertyuiopasdfgh",
    "qwertyqwertyqwerty",
    "letmeinletmein1",
    "welcome123456789",
    "changemechangeme",
    "adminadminadmin",
    "administrator123",
}


class AuthError(Exception):
    def __init__(self, message, status=400, retry_after=0):
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after


def password_error(password, username=USERNAME):
    if not isinstance(password, str):
        return "Enter a password."
    if not 15 <= len(password) <= 128:
        return "Use 15–128 characters for your password."
    candidate = password.casefold().strip()
    if candidate in COMMON_PASSWORDS or candidate == username.casefold() or len(set(candidate)) < 2:
        return "This password is too easy to guess. Choose a unique passphrase."
    return None


def _hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=2**15, r=8, p=3, dklen=32, maxmem=64 * 1024 * 1024
    )
    return f"scrypt$32768$8$3${salt.hex()}${digest.hex()}"


def _verify_password(password, stored):
    try:
        algorithm, n, r, p, salt, expected = stored.split("$")
        if algorithm != "scrypt" or (int(n), int(r), int(p)) != (32768, 8, 3):
            return False
        digest = hashlib.scrypt(
            password.encode("utf-8"),
            salt=bytes.fromhex(salt),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=32,
            maxmem=64 * 1024 * 1024,
        )
        return hmac.compare_digest(digest, bytes.fromhex(expected))
    except (ValueError, TypeError):
        return False


def _write_account(account):
    AUTH_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".account-", dir=AUTH_FILE.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(account, handle)
        os.chmod(name, 0o600)
        os.replace(name, AUTH_FILE)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def _account():
    if not AUTH_FILE.exists():
        account = {
            "username": USERNAME,
            "password_hash": _hash_password("Demo@1234"),
            "password_version": secrets.token_hex(16),
        }
        _write_account(account)
        return account
    return json.loads(AUTH_FILE.read_text(encoding="utf-8"))


def _retry_after(key):
    now = time.monotonic()
    item = _failures.get(key)
    if item and now >= item[1]:
        _failures.pop(key, None)
        item = None
    return max(1, math.ceil(item[1] - now)) if item and item[0] >= 5 else 0


def _failure(key):
    now = time.monotonic()
    count, expiry = _failures.get(key, (0, now + 900))
    if now >= expiry:
        count, expiry = 0, now + 900
    _failures[key] = (count + 1, expiry)
    _failures.move_to_end(key)
    while len(_failures) > 4096:
        _failures.popitem(last=False)
    return _retry_after(key)


def login(username, password):
    global _dummy
    with _lock:
        key = ("login", str(username).strip().casefold())
        retry = _retry_after(key)
        if retry:
            raise AuthError("Too many failed attempts. Try again later.", 429, retry)
        account = _account()
        if _dummy is None:
            _dummy = _hash_password(secrets.token_hex(16))
        valid = (
            isinstance(password, str)
            and len(password) <= 1024
            and _verify_password(
                password, account["password_hash"] if username == USERNAME else _dummy
            )
        )
        if not valid or username != USERNAME:
            retry = _failure(key)
            raise AuthError("Incorrect username or password.", 429 if retry else 401, retry)
        _failures.pop(key, None)
        token = secrets.token_urlsafe(32)
        session = {
            "username": USERNAME,
            "version": account["password_version"],
            "csrf": secrets.token_urlsafe(32),
            "expires": time.monotonic() + SESSION_SECONDS,
        }
        now = time.monotonic()
        for key, value in list(_sessions.items()):
            if value["expires"] <= now:
                _sessions.pop(key, None)
        if len(_sessions) >= 512:
            _sessions.pop(next(iter(_sessions)))
        _sessions[hashlib.sha256(token.encode()).digest()] = session
        return token, session


def current_session(cookie_header):
    cookie = SimpleCookie()
    try:
        cookie.load(cookie_header or "")
        token = cookie["soc_session"].value
    except (KeyError, TypeError):
        return None
    with _lock:
        session = _sessions.get(hashlib.sha256(token.encode()).digest())
        if not session or session["expires"] <= time.monotonic():
            return None
        if session["version"] != _account()["password_version"]:
            return None
        return session


def logout(cookie_header):
    cookie = SimpleCookie()
    try:
        cookie.load(cookie_header or "")
        token = cookie["soc_session"].value
    except (KeyError, TypeError):
        return
    with _lock:
        _sessions.pop(hashlib.sha256(token.encode()).digest(), None)


def change_password(session, current_password, new_password):
    with _lock:
        key = ("password-change", session["username"])
        retry = _retry_after(key)
        if retry:
            raise AuthError("Too many failed attempts. Try again later.", 429, retry)
        account = _account()
        valid = (
            isinstance(current_password, str)
            and len(current_password) <= 1024
            and _verify_password(current_password, account["password_hash"])
        )
        if not valid:
            retry = _failure(key)
            raise AuthError("Current password is incorrect.", 429 if retry else 400, retry)
        _failures.pop(key, None)
        error = password_error(new_password)
        if error:
            raise AuthError(error)
        if hmac.compare_digest(current_password.encode(), new_password.encode()):
            raise AuthError("Choose a password different from your current password.")
        account["password_hash"] = _hash_password(new_password)
        account["password_version"] = secrets.token_hex(16)
        _write_account(account)
        _sessions.clear()


def session_cookie(token):
    return f"soc_session={token}; HttpOnly; SameSite=Strict; Path=/api; Max-Age={SESSION_SECONDS}"


def clear_cookie():
    return "soc_session=; HttpOnly; SameSite=Strict; Path=/api; Max-Age=0"
