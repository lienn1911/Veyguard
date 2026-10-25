"""Serialize case investigations and reuse valid results without a background queue."""

import threading


class CaseAnalysisCoordinator:
    def __init__(self, assessment, service):
        self.assessment = assessment
        self.service = service
        self.lock = threading.RLock()
        self.running = None

    def investigate(self, incident_id, *, only_if_needed=False):
        with self.lock:
            if only_if_needed:
                current = self.assessment(incident_id)
                stale = (current.get("error") or {}).get("code") == "EVIDENCE_INTEGRITY_FAILED"
                if current.get("status") == "ready":
                    return {"status": "ok", "reused": True}
                if self.running or current.get("status") == "running":
                    return {"status": "busy"}
                if current.get("status") != "pending" and not stale:
                    return {"status": "skipped"}
            if self.running:
                raise ValueError("Another AI investigation is already running. Please wait.")
            self.running = incident_id
        try:
            return self.service().investigate(incident_id)
        finally:
            with self.lock:
                self.running = None
