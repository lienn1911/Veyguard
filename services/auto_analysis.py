"""Sequential, opt-in background AI investigation for existing cases."""

import json
import threading
import time
from pathlib import Path


class AutoAnalysis:
    def __init__(self, cases_path: Path, settings_path: Path, assessment, service):
        self.cases_path = cases_path
        self.settings_path = settings_path
        self.assessment = assessment
        self.service = service
        self.lock = threading.RLock()
        self.wake = threading.Event()
        self.running = None
        self.paused_reason = None
        self.enabled = self._load_enabled()
        self.worker = threading.Thread(target=self._loop, name='soc-auto-analysis', daemon=True)
        self.worker.start()

    def _load_enabled(self):
        try:
            return self.settings_path.exists() and json.loads(self.settings_path.read_text(encoding='utf-8')).get('enabled') is True
        except (OSError, ValueError, TypeError):
            return False

    def status(self):
        with self.lock:
            return {'enabled': self.enabled, 'running': self.running, 'paused_reason': self.paused_reason}

    def set_enabled(self, enabled):
        if not isinstance(enabled, bool):
            raise ValueError('enabled must be true or false')
        with self.lock:
            self.settings_path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.settings_path.with_suffix('.tmp')
            temporary.write_text(json.dumps({'enabled': enabled}), encoding='utf-8')
            temporary.replace(self.settings_path)
            self.enabled = enabled
            self.paused_reason = None
            self.wake.set()
            return self.status()

    def investigate(self, incident_id, *, only_if_needed=False):
        with self.lock:
            if only_if_needed:
                current = self.assessment(incident_id)
                stale = (current.get('error') or {}).get('code') == 'EVIDENCE_INTEGRITY_FAILED'
                if current.get('status') == 'ready':
                    return {'status': 'ok', 'reused': True}
                if self.running or current.get('status') == 'running':
                    return {'status': 'busy'}
                if current.get('status') != 'pending' and not stale:
                    return {'status': 'skipped'}
            if self.running:
                raise ValueError('Another AI investigation is already running. Please wait.')
            self.running = incident_id
        try:
            return self.service().investigate(incident_id)
        finally:
            with self.lock:
                self.running = None
                self.wake.set()

    def _loop(self):
        while True:
            self.wake.wait(15)
            self.wake.clear()
            with self.lock:
                if not self.enabled or self.running or self.paused_reason:
                    continue
            try:
                service = self.service()
                if service.settings.is_mock:
                    with self.lock:
                        self.paused_reason = 'Connect a live AI provider to use automatic investigation.'
                    continue
                cases = json.loads(self.cases_path.read_text(encoding='utf-8')).get('incidents', [])
                for case in cases:
                    with self.lock:
                        if not self.enabled or self.running or self.paused_reason:
                            break
                    incident_id = case['incident_id']
                    # Failed cases require an explicit manual retry; never spend quota in a retry loop.
                    if self.assessment(incident_id).get('status') != 'pending':
                        continue
                    try:
                        result = self.investigate(incident_id)
                        if result.get('status') != 'ok':
                            error = result.get('error') or {}
                            with self.lock:
                                self.paused_reason = ('Provider quota or rate limit reached.' if error.get('code') == 'PROVIDER_RATE_LIMITED'
                                                      else 'An AI investigation failed. Check the case and resume automatic investigation.')
                            break
                    except Exception:
                        with self.lock:
                            self.paused_reason = 'An AI investigation failed. Check the case and resume automatic investigation.'
                        break
                    time.sleep(2)
            except Exception:
                with self.lock:
                    self.paused_reason = 'Automatic investigation could not read the case queue.'
