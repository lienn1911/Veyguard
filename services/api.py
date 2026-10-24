import json
import os
import secrets
import sqlite3
import threading
from contextlib import closing
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from services.recommendations import DB_PATH, annotate_ai_next_steps, generate_recommendations, get_case_note, init_db, log_event, save_decision
from services.case_notes import add_note, list_notes
from services.config import ConfigError, load_settings, proposed_ai_settings, save_ai_settings
from services.ai_settings import test_connection
from services.providers import describe_providers
from services.data_store import Dataset
from services.raw_flows import database_status, query_case_flows
from services.triage import TriageService
from services.unified_audit import append_in_transaction, entries as audit_entries, initialize as initialize_audit, verify as verify_audit
from services import auth
from services.auto_analysis import AutoAnalysis
from services.review_priority import effective_priority, latest_overrides, save_priority
from services.validation import check_case_time_claims


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / 'src' / 'real-alerts.json'
_ai_service = None
_auto_analysis = None
_auto_lock = threading.Lock()


def auto_analysis():
    global _auto_analysis
    with _auto_lock:
        if _auto_analysis is None:
            _auto_analysis = AutoAnalysis(DATA, ROOT / 'data' / 'auto-analysis.json', ai_assessment, ai_service)
        return _auto_analysis


def ai_service():
    global _ai_service
    if _ai_service is None:
        settings = load_settings()
        dataset = Dataset.load(settings.alerts_path, settings.timelines_path)
        _ai_service = TriageService(settings, dataset)
    return _ai_service


def public_ai_settings(settings):
    return {"current": settings.describe(), "providers": [item for item in describe_providers(settings) if item["implemented"] and item["id"] != "mock"]}


def ai_assessment(incident_id):
    service = ai_service()
    if service.settings.is_mock:
        return {'status': 'not_configured', 'assessment': None, 'mode': 'mock'}
    progress = service.progress(incident_id)
    if progress and progress['running']:
        return {'status': 'running', 'assessment': None, 'mode': service.status()['mode'], 'progress': progress}
    stored = service.latest(incident_id)
    latest = stored.get('latest') if stored else None
    if not latest or latest.get('provider') != service.settings.provider or latest.get('model') != service.settings.model:
        return {'status': 'pending', 'assessment': None, 'mode': service.status()['mode']}
    trace = latest.get('investigation') or {}
    investigation = {
        'steps': trace.get('steps', 0),
        'tool_calls': [{
            'tool': call.get('tool'), 'step': call.get('step'), 'ok': call.get('ok'),
            'blocked': call.get('blocked'), 'duration_ms': call.get('duration_ms'),
            'error_code': (call.get('error') or {}).get('code'),
            'result_count': call.get('result_count'),
            'arguments': {key: value for key, value in (call.get('arguments') or {}).items()
                          if key in ('incident_id', 'limit')},
        } for call in trace.get('tool_calls', [])],
    }
    run = {'run_metadata': {key: latest.get(key) for key in ('started_at', 'completed_at', 'duration_ms')},
           'validation': latest.get('validation'),
           'provider': latest.get('provider'), 'model': latest.get('model'),
           'run_id': latest.get('run_id'), 'investigation': investigation}
    if latest['status'] != 'ok':
        return {'status': 'unavailable', 'assessment': None, 'mode': service.status()['mode'], 'error': latest.get('error'), **run}
    return {'status': 'ready', 'mode': service.status()['mode'], **run, 'decision': (stored.get('decision') or {'status': 'pending'}), 'assessment': {
        'verdict': latest['verdict'], 'confidence': latest['confidence'], 'summary': latest['reason'],
        'evidence_ids': latest['evidence_ids'], 'findings': latest['findings'], 'limitations': latest['limitations'],
        'technique_mappings': latest.get('technique_mappings') or [],
        'next_steps': (latest.get('proposal') or {}).get('next_steps') or [],
        'requires_confirmation': latest['requires_confirmation'], 'run_id': latest['run_id'],
    }}


def audit_events(incident_id):
    return [{'time': item['ts'], 'action': item['event'], **item['payload'], 'actor': item['actor']}
            for item in audit_entries(DB_PATH, incident_id=incident_id)]


def saved_decisions(incident_id):
    init_db(DB_PATH)
    with closing(sqlite3.connect(DB_PATH)) as db:
        rows = db.execute('SELECT recommendation_id, decision FROM decisions WHERE incident_id = ?', (incident_id,)).fetchall()
    return {item_id: decision.lower() for item_id, decision in rows}


def saved_decision_remarks(incident_id):
    init_db(DB_PATH)
    with closing(sqlite3.connect(DB_PATH)) as db:
        rows = db.execute('SELECT recommendation_id, remark FROM decisions WHERE incident_id = ?', (incident_id,)).fetchall()
    return {item_id: remark or '' for item_id, remark in rows}


def case_record(data, incident_id):
    if not any(item['incident_id'] == incident_id for item in data['incidents']):
        raise ValueError('Unknown case')
    events = audit_entries(DB_PATH, incident_id=incident_id)

    saved = next(
        (item for item in reversed(events)
         if item['event'] == 'CASE_RECORD_SAVED'),
        None
    )

    resolved = next(
        (item for item in reversed(events)
         if item['event'] == 'CASE_RESOLVED'),
        None
    )

    if saved:
        record = dict(saved['payload'])
        incident = next(item for item in data['incidents'] if item['incident_id'] == incident_id)
        alerts = [item for item in data['alerts'] if item['alert_id'] in incident['alert_ids']]
        current = ai_assessment(incident_id) if record.get('ai_run_id') else {}
        invalid_run = (current.get('run_id') == record.get('ai_run_id') and
                       (current.get('error') or {}).get('code') == 'EVIDENCE_INTEGRITY_FAILED')
        if record.get('ai_summary') and (invalid_run or check_case_time_claims(record['ai_summary'], incident, alerts)):
            record.update(ai_summary=None, ai_verdict=None, ai_decision=None, ai_findings=[], ai_mappings=[], ai_evidence_ids=[], ai_confidence=None, ai_limitations=None, ai_status='unavailable',
                          ai_error='The historical AI summary conflicts with the recorded case time range. The original audit snapshot is retained; rerun investigation before relying on the AI conclusion.')
        return {
            'status': 'resolved' if resolved else 'saved',
            'record': record,
            'event_id': saved['event_id'],
            'saved_at': saved['ts'],
            'resolution': resolved['payload'] if resolved else None,
            'resolved_at': resolved['ts'] if resolved else None
        }
    decisions = saved_decisions(incident_id)
    decision_remarks = saved_decision_remarks(incident_id)
    checks = generate_recommendations(data, incident_id)
    assessment = ai_assessment(incident_id)
    ai_result = assessment.get('assessment') if assessment.get('status') == 'ready' else None
    plan_checks = annotate_ai_next_steps(checks, (ai_result or {}).get('next_steps', []))
    incident = next(item for item in data['incidents'] if item['incident_id'] == incident_id)
    priority_event = next((item for item in reversed(events) if item['event'] == 'CASE_REVIEW_PRIORITY_SET'), None)
    return {'status': 'ready', 'record': {
        'review_priority': effective_priority(data, incident, priority_event['payload'] if priority_event else None),
        'case_summary': case_summary(data, incident_id),
        'ai_investigation': assessment.get('investigation'),
        'ai_run_metadata': assessment.get('run_metadata'),
        'ai_validation': assessment.get('validation'),
        'ai_evidence_ids': ai_result.get('evidence_ids', []) if ai_result else [],
        'ai_confidence': ai_result.get('confidence') if ai_result else None,
        'ai_findings': ai_result.get('findings', []) if ai_result else [],
        'ai_limitations': ai_result.get('limitations') if ai_result else None,
        'ai_mappings': ai_result.get('technique_mappings', []) if ai_result else [],
        'analyst_review': assessment.get('decision'),
        'investigation_notes': list_notes(incident_id, db_path=DB_PATH),
        'activity': events,
        'investigation_steps': [{'id': check['id'], 'text': check['description'], 'decision': decisions.get(check['id']), 'remark': decision_remarks.get(check['id'], ''),
            'evidence_ids': check.get('ai_evidence_ids') or check.get('evidence_ids', []), 'reason': check.get('ai_reason'),
            'events': [event for event in events if event['payload'].get('recommendation_id') == check['id']]} for check in plan_checks if check.get('ai_suggested') or check['id'] in decisions],
        'ai_summary': ai_result.get('summary') if ai_result else None,
        'ai_verdict': ai_result.get('verdict') if ai_result else None,
        'ai_run_id': ai_result.get('run_id') if ai_result else None,
        'ai_decision': (assessment.get('decision') or {}).get('status') if ai_result else None,
        'ai_status': assessment.get('status'),
        'ai_error': (assessment.get('error') or {}).get('message') if isinstance(assessment.get('error'), dict) else None,
        'approved_checks': sum(value == 'approved' for value in decisions.values()),
        'rejected_checks': sum(value == 'rejected' for value in decisions.values()),
        'total_checks': len(checks),
    }}


def save_case_record(data, incident_id, analyst):
    if not isinstance(analyst, str) or not analyst.strip() or len(analyst.strip()) > 80:
        raise ValueError('Analyst name is required')
    prepared = case_record(data, incident_id)
    if prepared['status'] in ('saved', 'resolved'):
        return prepared
    with closing(sqlite3.connect(DB_PATH, timeout=30)) as db, db:
        db.execute('BEGIN IMMEDIATE')
        existing = db.execute("SELECT event_id, ts, payload FROM audit_events WHERE incident_id = ? AND event = 'CASE_RECORD_SAVED' ORDER BY seq DESC LIMIT 1", (incident_id,)).fetchone()
        if existing:
            return {'status': 'saved', 'event_id': existing[0], 'saved_at': existing[1], 'record': json.loads(existing[2])}
        event = append_in_transaction(db, 'CASE_RECORD_SAVED', incident_id=incident_id,
                                      actor=f'analyst:{analyst.strip()}', payload=prepared['record'])
    return {'status': 'saved', 'event_id': event['event_id'], 'saved_at': event['ts'], 'record': event['payload']}


def resolve_case(data, incident_id, analyst, reason, confirmed):
    if not any(
        item['incident_id'] == incident_id
        for item in data['incidents']
    ):
        raise ValueError('Unknown case')

    if not isinstance(analyst, str) or not analyst.strip():
        raise ValueError('Analyst is required')

    if not isinstance(reason, str) or not 10 <= len(reason.strip()) <= 1000:
        raise ValueError('Resolution reason must be 10-1000 characters')

    if confirmed is not True:
        raise ValueError('Explicit analyst confirmation is required')

    init_db()
    initialize_audit(DB_PATH)

    with closing(sqlite3.connect(DB_PATH, timeout=30)) as db, db:
        db.execute('BEGIN IMMEDIATE')

        existing = db.execute(
            """
            SELECT event_id, ts, payload
            FROM audit_events
            WHERE incident_id = ? AND event = 'CASE_RESOLVED'
            ORDER BY seq DESC LIMIT 1
            """,
            (incident_id,)
        ).fetchone()

        if existing:
            return {
                'status': 'resolved',
                'event_id': existing[0],
                'resolved_at': existing[1],
                'resolution': json.loads(existing[2])
            }

        saved = db.execute(
            """
            SELECT 1 FROM audit_events
            WHERE incident_id = ? AND event = 'CASE_RECORD_SAVED'
            LIMIT 1
            """,
            (incident_id,)
        ).fetchone()

        if not saved:
            raise ValueError('Save the case record before resolving')

        event = append_in_transaction(
            db,
            'CASE_RESOLVED',
            incident_id=incident_id,
            actor=f'analyst:{analyst.strip()}',
            payload={
                'analyst_id': analyst.strip(),
                'reason': reason.strip(),
                'confirmed_by_analyst': True
            }
        )

    return {
        'status': 'resolved',
        'event_id': event['event_id'],
        'resolved_at': event['ts'],
        'resolution': event['payload']
    }

def case_summary(data, incident_id):
    incident = next(item for item in data['incidents'] if item['incident_id'] == incident_id)
    return f"{len(incident['alert_ids'])} alerts from {incident['source_ip']} to {incident['destination_ip']} between {incident['window_start'].replace('T', ' ')} and {incident['window_end'].replace('T', ' ')}."


def review_progress(ready, ai_decision, required_ids, decisions):
    """Review is complete only for a current AI result and every proposed step."""
    ai_reviewed = ready and ai_decision in ('confirmed', 'rejected')
    reviewed = sum(str(decisions.get(item, '')).lower() in ('approved', 'rejected') for item in required_ids)
    done = int(ai_reviewed) + reviewed
    total = 1 + len(required_ids)
    status = 'complete' if ready and done == total else 'partial' if done else 'pending'
    return {'state': status, 'reviewed': done, 'total': total, 'ai_reviewed': bool(ai_reviewed),
            'steps_reviewed': reviewed, 'steps_total': len(required_ids)}


def case_queue(data):
    init_db()
    initialize_audit(DB_PATH)
    with closing(sqlite3.connect(DB_PATH)) as db:
        db.execute('CREATE TABLE IF NOT EXISTS case_assignments (incident_id TEXT PRIMARY KEY, analyst_id TEXT NOT NULL, assigned_at TEXT NOT NULL)')
        owners = dict(db.execute('SELECT incident_id, analyst_id FROM case_assignments'))
        activity = dict(db.execute('SELECT incident_id, MAX(ts) FROM audit_events GROUP BY incident_id')) if db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_events'").fetchone() else {}
        analyst_activity = {row[0] for row in db.execute("SELECT DISTINCT incident_id FROM audit_events WHERE event = 'ANALYST_NOTE_ADDED'")}
        priority_overrides = latest_overrides(db)
        resolved_cases = {
            row[0]
            for row in db.execute(
                """
                SELECT DISTINCT incident_id
                FROM audit_events
                WHERE event = 'CASE_RESOLVED'
                """
            )
        }
        saved_reports = {row[0]: {'event_id': row[1], 'saved_at': row[2], 'saved_by': row[3]}
                         for row in db.execute("SELECT incident_id, event_id, ts, actor FROM audit_events WHERE event = 'CASE_RECORD_SAVED' ORDER BY seq")}
        decision_ids = {}
        for row in db.execute('SELECT incident_id, recommendation_id, decision FROM decisions'):
            decision_ids.setdefault(row[0], {})[row[1]] = row[2]
        check_decisions = {}
        for incident_id, decision in db.execute('SELECT incident_id, decision FROM decisions'):
            check_decisions.setdefault(incident_id, []).append(decision)
        completed = {row[0]: row[1] for row in db.execute('''
            SELECT d.incident_id, COUNT(t.recommendation_id)
            FROM decisions d LEFT JOIN task_completions t ON t.recommendation_id = d.recommendation_id
            WHERE d.decision = 'APPROVED'
            GROUP BY d.incident_id
        ''')}
    triage = ai_service()
    expected_checks = {incident['incident_id']: len(generate_recommendations(data, incident['incident_id']))
                       for incident in data['incidents']}

    def has_pending_approval(incident_id):
        stored = triage.latest(incident_id) or {}
        latest = stored.get('latest') or {}
        ready = (not triage.settings.is_mock and latest.get('status') == 'ok'
                 and latest.get('provider') == triage.settings.provider
                 and latest.get('model') == triage.settings.model)
        return bool(incident_id not in resolved_cases and ready and (
            (stored.get('decision') or {}).get('status', 'pending') == 'pending'
            or (expected_checks[incident_id] > 0 and not check_decisions.get(incident_id)
                and (latest.get('proposal') or {}).get('next_steps'))))

    def progress_for(incident_id):
        stored = triage.latest(incident_id) or {}
        latest = stored.get('latest') or {}
        ready = (not triage.settings.is_mock and latest.get('status') == 'ok'
                 and latest.get('provider') == triage.settings.provider
                 and latest.get('model') == triage.settings.model)
        proposal = latest.get('proposal') or {}
        incident = next(item for item in data['incidents'] if item['incident_id'] == incident_id)
        alerts = [item for item in data['alerts'] if item['alert_id'] in incident['alert_ids']]
        if ready and check_case_time_claims(proposal.get('summary', ''), incident, alerts):
            ready = False
        checks = annotate_ai_next_steps(generate_recommendations(data, incident_id), proposal.get('next_steps', []) if ready else [])
        required = [item['id'] for item in checks if item.get('ai_suggested')]
        if not ready:
            required = list(decision_ids.get(incident_id, {}))
        return review_progress(ready, (stored.get('decision') or {}).get('status'), required, decision_ids.get(incident_id, {}))

    def checks_complete(incident_id):
        return bool(check_decisions.get(incident_id))
    def status_for(incident_id):
        if incident_id in resolved_cases:
            return 'Resolved'

        checks = check_decisions.get(incident_id, [])
        if checks:
            approved = checks.count('APPROVED')
            if approved == len(checks):
                return 'Approved steps completed' if completed.get(incident_id, 0) == approved else 'Next steps approved'
            if approved:
                return 'Partially approved'
            return 'Next steps rejected'
        stored = triage.latest(incident_id) or {}
        ai_decision = (stored.get('decision') or {}).get('status')
        if ai_decision == 'confirmed':
            return 'AI assessment confirmed'
        if ai_decision == 'rejected':
            return 'AI assessment rejected'
        if incident_id in owners or incident_id in analyst_activity:
            return 'In review'
        latest = stored.get('latest') or {}
        if (not triage.settings.is_mock and latest.get('status') == 'ok'
                and latest.get('provider') == triage.settings.provider
                and latest.get('model') == triage.settings.model):
            return 'AI ready for review'
        return 'Not reviewed'

    return {
        incident['incident_id']: {
            'status': status_for(incident['incident_id']),
            'case_status': (
                'Resolved'
                if incident['incident_id'] in resolved_cases
                else 'Open'
            ),
            'pending_approval': has_pending_approval(
                incident['incident_id']
            ),
            'review_complete': checks_complete(
                incident['incident_id']
            ),
            'review_progress': progress_for(incident['incident_id']),
            'saved_report': saved_reports.get(incident['incident_id']),
            'owner': owners.get(incident['incident_id']),
            'review_priority': effective_priority(data, incident, priority_overrides.get(incident['incident_id'])),
            'last_activity': activity.get(incident['incident_id']),
        }
        for incident in data['incidents']
    }


def pending_tasks():
    init_db()
    with closing(sqlite3.connect(DB_PATH)) as db:
        rows = db.execute(
            """
            SELECT d.recommendation_id, d.incident_id, d.description, d.analyst_id
            FROM decisions d
            LEFT JOIN task_completions t ON t.recommendation_id = d.recommendation_id
            WHERE d.decision = 'APPROVED' AND t.recommendation_id IS NULL
            ORDER BY d.incident_id, d.recommendation_id
            """
        ).fetchall()
    return [{'id': task_id, 'incident_id': incident_id, 'text': description, 'approved_by': analyst}
            for task_id, incident_id, description, analyst in rows]


def complete_task(recommendation_id, analyst):
    if not isinstance(analyst, str) or not analyst.strip() or len(analyst.strip()) > 80:
        raise ValueError('Analyst name is required')
    init_db()
    timestamp = datetime.now(timezone.utc).isoformat()
    with closing(sqlite3.connect(DB_PATH)) as db, db:
        row = db.execute('SELECT incident_id FROM decisions WHERE recommendation_id = ? AND decision = ?',
                         (recommendation_id, 'APPROVED')).fetchone()
        if not row:
            raise ValueError('Approved task not found')
        if db.execute('SELECT 1 FROM task_completions WHERE recommendation_id = ?', (recommendation_id,)).fetchone():
            raise ValueError('Task already completed')
        db.execute('INSERT INTO task_completions VALUES (?, ?, ?)', (recommendation_id, analyst.strip(), timestamp))
        append_in_transaction(db, 'INVESTIGATION_STEP_COMPLETED', incident_id=row[0], actor=f'analyst:{analyst.strip()}',
                              payload={'recommendation_id': recommendation_id, 'analyst_id': analyst.strip()})
    return row[0]


class Handler(BaseHTTPRequestHandler):
    def send_json(self, status, payload, extra_headers=None):
        body = json.dumps(payload).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        origin = self.headers.get('Origin')
        if origin in {'http://127.0.0.1:5173', 'http://127.0.0.1:5174', 'http://localhost:5173', 'http://localhost:5174'}:
            self.send_header('Access-Control-Allow-Origin', origin)
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, X-SOC-Desk-Settings, X-SOC-Desk-Auth, X-CSRF-Token')
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_json(204, {})

    def request_body(self, max_size=4096):
        if self.headers.get('Content-Type', '').split(';')[0].strip() != 'application/json':
            raise ValueError('JSON request required')
        length = int(self.headers.get('Content-Length', '0'))
        if length < 2 or length > max_size:
            raise ValueError('Invalid request size')
        payload = json.loads(self.rfile.read(length))
        if not isinstance(payload, dict):
            raise ValueError('Invalid request data')
        return payload

    def allowed_origin(self):
        origin = self.headers.get('Origin')
        allowed = {'http://127.0.0.1:5173', 'http://127.0.0.1:5174', 'http://localhost:5173', 'http://localhost:5174', 'http://127.0.0.1:8765'}
        extra = os.environ.get('SOC_TRIAGE_EXTRA_ORIGINS', '')
        allowed.update(o.strip() for o in extra.split(',') if o.strip())
        return not origin or origin in allowed

    def require_session(self):
        session = auth.current_session(self.headers.get('Cookie'))
        if not session:
            self.send_json(401, {'error': 'Please sign in again.'})
        return session

    def require_csrf(self, session):
        token = self.headers.get('X-CSRF-Token', '')
        if not token or not secrets.compare_digest(token, session['csrf']):
            raise auth.AuthError('Session token is missing or expired.', 403)

    def route(self):
        parts = urlsplit(self.path).path.strip('/').split('/')
        if len(parts) != 4 or parts[:2] != ['api', 'cases']:
            raise ValueError('Unknown endpoint')
        return unquote(parts[2]), parts[3]

    def do_GET(self):
        try:
            path = urlsplit(self.path)
            if path.path == '/api/auth/session':
                session = auth.current_session(self.headers.get('Cookie'))
                self.send_json(200, {'authenticated': bool(session), 'username': session['username'] if session else None, 'csrf_token': session['csrf'] if session else None})
                return
            if not self.require_session():
                return
            if path.path == '/api/ai/settings':
                self.send_json(200, public_ai_settings(load_settings()))
                return
            if path.path == '/api/ai/auto-analysis':
                self.send_json(200, auto_analysis().status())
                return
            if path.path == '/api/audit':
                raw_limit = parse_qs(path.query).get('limit', ['100'])[0]
                limit = max(1, min(int(raw_limit), 500))
                self.send_json(200, {'entries': audit_entries(DB_PATH, limit=limit), 'verification': verify_audit(DB_PATH)})
                return
            if path.path == '/api/audit/verify':
                self.send_json(200, verify_audit(DB_PATH))
                return
            if urlsplit(self.path).path == '/api/tasks':
                self.send_json(200, {'tasks': pending_tasks()})
                return
            if urlsplit(self.path).path == '/api/cases/queue':
                self.send_json(200, {'cases': case_queue(json.loads(DATA.read_text(encoding='utf-8')))})
                return
            incident_id, action = self.route()
            data = json.loads(DATA.read_text(encoding='utf-8'))
            if action == 'raw-flows':
                incident = next((item for item in data['incidents'] if item['incident_id'] == incident_id), None)
                if not incident:
                    raise ValueError('Unknown case')
                status = database_status()
                if not status['available']:
                    self.send_json(200, status)
                    return
                query = parse_qs(path.query)
                case_alerts = [item for item in data['alerts'] if item['alert_id'] in incident['alert_ids']]
                result = query_case_flows(incident, case_alerts,
                                          minute=query.get('minute', [None])[0],
                                          page=int(query.get('page', ['1'])[0]))
                self.send_json(200, {'available': True, **result})
            elif action == 'recommendations':
                recommendations = generate_recommendations(data, incident_id)
                assessment = ai_assessment(incident_id)
                ai_ready = assessment.get('status') == 'ready'
                presented = annotate_ai_next_steps(recommendations, (assessment.get('assessment') or {}).get('next_steps') if ai_ready else [])
                decisions = saved_decisions(incident_id)
                note = get_case_note(incident_id) if 'approved' in decisions.values() else None
                if note:
                    note['summary'] = case_summary(data, incident_id)
                    note['approved_checks'] = [{'id': item['id'], 'text': item['description']} for item in recommendations if decisions.get(item['id']) == 'approved']
                self.send_json(200, {'incident_id': incident_id, 'ai_status': assessment.get('status'), 'checks': [{'id': item['id'], 'action': item['action'], 'text': item['description'], 'evidence_ids': item['evidence_ids'], 'ai_suggested': item['ai_suggested'], 'ai_reason': item.get('ai_reason'), 'ai_evidence_ids': item.get('ai_evidence_ids', [])} for item in presented], 'decisions': decisions, 'remarks': saved_decision_remarks(incident_id), 'note': note})
            elif action == 'audit':
                if not any(item['incident_id'] == incident_id for item in data['incidents']):
                    raise ValueError('Unknown case')
                self.send_json(200, {'events': audit_events(incident_id)})
            elif action == 'report-pdf':
                from services.report_pdf import build_report_pdf
                report = case_record(data, incident_id)
                incident = next(item for item in data['incidents'] if item['incident_id'] == incident_id)
                alerts = [item for item in data['alerts'] if item['alert_id'] in incident['alert_ids']]
                flows = [item for item in data.get('flows', []) if item.get('flow_id') in incident.get('evidence_sample_ids', [])]
                pdf = build_report_pdf(incident_id, incident, alerts, flows, report)
                safe_name = ''.join(c for c in incident_id if c.isalnum() or c in '-_')
                self.send_response(200)
                self.send_header('Content-Type', 'application/pdf')
                self.send_header('Content-Disposition', f'attachment; filename="Triage-report-{safe_name}.pdf"')
                self.send_header('Content-Length', str(len(pdf)))
                self.send_header('Cache-Control', 'no-store')
                self.end_headers()
                self.wfile.write(pdf)
            elif action == 'record':
                self.send_json(200, case_record(data, incident_id))
            elif action == 'notes':
                if not any(item['incident_id'] == incident_id for item in data['incidents']):
                    raise ValueError('Unknown case')
                self.send_json(200, {'notes': list_notes(incident_id, db_path=DB_PATH)})
            elif action == 'ai-assessment':
                if not any(item['incident_id'] == incident_id for item in data['incidents']):
                    raise ValueError('Unknown case')
                try:
                    self.send_json(200, ai_assessment(incident_id))
                except Exception as error:
                    self.send_json(503, {'status': 'unavailable', 'assessment': None, 'error': {'message': str(error)}})
            else:
                raise ValueError('Unknown endpoint')
        except ValueError as error:
            self.send_json(400, {'error': str(error)})

    def do_POST(self):
        try:
            if not self.allowed_origin():
                self.send_json(403, {'error': 'Untrusted origin'})
                return
            path = urlsplit(self.path).path
            if path == '/api/auth/login':
                if self.headers.get('X-SOC-Desk-Auth') != '1':
                    raise auth.AuthError('Invalid login request.', 403)
                payload = self.request_body()
                token, session = auth.login(payload.get('username'), payload.get('password'))
                self.send_json(200, {'username': session['username'], 'csrf_token': session['csrf']}, {'Set-Cookie': auth.session_cookie(token)})
                return
            session = self.require_session()
            if not session:
                return
            if path == '/api/auth/logout':
                self.require_csrf(session)
                auth.logout(self.headers.get('Cookie'))
                self.send_json(200, {'signed_out': True}, {'Set-Cookie': auth.clear_cookie()})
                return
            if path == '/api/auth/change-password':
                self.require_csrf(session)
                payload = self.request_body()
                auth.change_password(session, payload.get('current_password'), payload.get('new_password'))
                self.send_json(200, {'changed': True}, {'Set-Cookie': auth.clear_cookie()})
                return
            if path == '/api/ai/auto-analysis':
                self.require_csrf(session)
                self.send_json(200, auto_analysis().set_enabled(self.request_body().get('enabled')))
                return
            self.require_csrf(session)
            settings_path = urlsplit(self.path).path
            if settings_path in {'/api/ai/settings', '/api/ai/settings/test'}:
                origin = self.headers.get('Origin')
                if origin and origin not in {'http://127.0.0.1:5173', 'http://127.0.0.1:5174', 'http://localhost:5173', 'http://localhost:5174'}:
                    self.send_json(403, {'error': 'Untrusted origin'})
                    return
                if self.headers.get('X-SOC-Desk-Settings') != '1' or self.headers.get('Content-Type', '').split(';')[0].strip() != 'application/json':
                    self.send_json(400, {'error': 'Invalid settings request'})
                    return
                length = int(self.headers.get('Content-Length', '0'))
                if length < 2 or length > 2048:
                    raise ValueError('Invalid request size')
                request = json.loads(self.rfile.read(length))
                if not isinstance(request, dict):
                    raise ValueError('Invalid settings request')
                settings, candidate = proposed_ai_settings(request.get('provider'), request.get('model'), request.get('api_key', ''))
                if settings_path.endswith('/test'):
                    result = test_connection(settings)
                    self.send_json(200 if result['ok'] else 422, result)
                else:
                    save_ai_settings(candidate)
                    global _ai_service
                    _ai_service = None
                    self.send_json(200, public_ai_settings(settings))
                return
            task_parts = urlsplit(self.path).path.strip('/').split('/')
            if len(task_parts) == 4 and task_parts[:2] == ['api', 'tasks'] and task_parts[3] == 'complete':
                length = int(self.headers.get('Content-Length', '0'))
                if length < 1 or length > 1024:
                    raise ValueError('Invalid request size')
                request = json.loads(self.rfile.read(length))
                if request.get('analyst') != session['username']:
                    raise ValueError('The signed-in analyst must match the reviewer')
                incident_id = complete_task(unquote(task_parts[2]), session['username'])
                self.send_json(200, {'incident_id': incident_id, 'tasks': pending_tasks()})
                return
            incident_id, action = self.route()
            if action in ('ai-assessment', 'auto-check'):
                if not any(item['incident_id'] == incident_id for item in json.loads(DATA.read_text(encoding='utf-8'))['incidents']):
                    raise ValueError('Unknown case')
                try:
                    if ai_service().settings.is_mock:
                        self.send_json(409, {'status': 'not_configured', 'assessment': None, 'error': {'message': 'Connect a live AI provider in Settings before running AI check.'}})
                        return
                    if action == 'auto-check':
                        self.request_body()
                        result = auto_analysis().investigate(incident_id, only_if_needed=True)
                    else:
                        result = auto_analysis().investigate(incident_id)
                    payload = ai_assessment(incident_id)
                    if result['status'] == 'busy':
                        payload['queued'] = True
                    self.send_json(202 if result['status'] == 'busy' else 200 if result['status'] in ('ok', 'skipped') else 502, payload)
                except Exception as error:
                    self.send_json(503, {'status': 'unavailable', 'assessment': None, 'error': {'message': str(error)}})
                return

            if action == 'resolve':
                request = self.request_body()

                if request.get('analyst') != session['username']:
                    raise ValueError('Signed-in analyst must match reviewer')

                resolve_case(
                    json.loads(DATA.read_text(encoding='utf-8')),
                    incident_id,
                    session['username'],
                    request.get('reason'),
                    request.get('confirmed')
                )

                data = json.loads(DATA.read_text(encoding='utf-8'))
                self.send_json(200, case_record(data, incident_id))
                return

            if action not in {'approval', 'assign', 'notes', 'ai-decision', 'record', 'priority'}:
                raise ValueError('Unknown endpoint')
            length = int(self.headers.get('Content-Length', '0'))
            if length < 1 or length > 16384:
                raise ValueError('Invalid request size')
            request = json.loads(self.rfile.read(length))
            data = json.loads(DATA.read_text(encoding='utf-8'))
            if not isinstance(request, dict):
                raise ValueError('JSON request must be an object')
            if action == 'priority':
                if request.get('analyst') != session['username']:
                    raise ValueError('The signed-in analyst must match the reviewer')
                priority = save_priority(data, incident_id, request.get('level'), request.get('reason'),
                                         session['username'], request.get('confirmed'), DB_PATH)
                self.send_json(200, {'review_priority': priority})
                return
            if action == 'record':
                if request.get('analyst') != session['username']:
                    raise ValueError('The signed-in analyst must match the reviewer')
                self.send_json(200, save_case_record(data, incident_id, session['username']))
                return
            if action == 'ai-decision':
                if not any(item['incident_id'] == incident_id for item in data['incidents']):
                    raise ValueError('Unknown case')
                if request.get('analyst') != session['username']:
                    raise ValueError('The signed-in analyst must match the reviewer')
                decision = ai_service().decide(incident_id, decision=request.get('decision'), analyst=session['username'], note=request.get('note'))
                self.send_json(200, {'decision': decision['decision'], 'assessment': ai_assessment(incident_id)})
                return
            if action == 'notes':
                if request.get('analyst') != session['username']:
                    raise ValueError('The signed-in analyst must match the reviewer')
                note = add_note(data, incident_id, session['username'], request.get('evidence_id'), request.get('text'), db_path=DB_PATH)
                self.send_json(200, {'note': note})
                return
            if action == 'assign':
                if not any(item['incident_id'] == incident_id for item in data['incidents']):
                    raise ValueError('Unknown case')
                analyst = request.get('analyst')
                if not isinstance(analyst, str) or not analyst.strip() or len(analyst.strip()) > 80:
                    raise ValueError('Analyst name is required')
                init_db()
                timestamp = datetime.now(timezone.utc).isoformat()
                with closing(sqlite3.connect(DB_PATH)) as db, db:
                    db.execute('CREATE TABLE IF NOT EXISTS case_assignments (incident_id TEXT PRIMARY KEY, analyst_id TEXT NOT NULL, assigned_at TEXT NOT NULL)')
                    if db.execute('SELECT 1 FROM case_assignments WHERE incident_id = ?', (incident_id,)).fetchone():
                        raise ValueError('Case is already assigned')
                    db.execute('INSERT INTO case_assignments VALUES (?, ?, ?)', (incident_id, analyst.strip(), timestamp))
                    append_in_transaction(db, 'CASE_ASSIGNED', incident_id=incident_id, actor=f"analyst:{session['username']}",
                                          payload={'analyst_id': analyst.strip()})
                self.send_json(200, {'case': case_queue(data)[incident_id]})
                return
            recommendations = generate_recommendations(data, incident_id)
            assessment = ai_assessment(incident_id)
            if (assessment.get('error') or {}).get('code') == 'EVIDENCE_INTEGRITY_FAILED':
                raise ValueError('Rerun AI investigation: the saved result conflicts with current evidence and cannot support approval.')
            decisions = request.get('decisions')
            remarks = request.get('remarks', {})
            analyst = request.get('analyst')
            ids = {item['id'] for item in recommendations}
            if analyst != session['username']:
                raise ValueError('The signed-in analyst must match the reviewer')
            if not isinstance(analyst, str) or not analyst.strip() or not isinstance(decisions, dict) or not decisions or set(decisions) - ids or set(decisions.values()) - {'approved', 'rejected'}:
                raise ValueError('Select valid investigation steps to approve or reject')
            if not isinstance(remarks, dict) or set(remarks) - set(decisions) or any(not isinstance(value, str) or len(value.strip()) > 1000 for value in remarks.values()):
                raise ValueError('Remarks must be text of at most 1000 characters for reviewed steps')
            init_db()
            with closing(sqlite3.connect(DB_PATH)) as db:
                existing = db.execute('SELECT recommendation_id FROM decisions WHERE incident_id = ?', (incident_id,)).fetchall()
            if existing:
                raise ValueError('Decisions for this case have already been saved')
            for item in recommendations:
                if item['id'] in decisions:
                    save_decision(data, incident_id, item['id'], decisions[item['id']].upper(), analyst, 'Needs Review', remark=remarks.get(item['id'], ''))
            note = None
            if 'approved' in decisions.values():
                note = get_case_note(incident_id)
                note['summary'] = case_summary(data, incident_id)
                note['approved_checks'] = [{'id': item['id'], 'text': item['description']} for item in recommendations if decisions.get(item['id']) == 'approved']
                log_event(incident_id, 'CASE_NOTE_DRAFTED', {'analyst_id': analyst.strip(), 'evidence_ids': sorted({e for item in recommendations if decisions.get(item['id']) == 'approved' for e in item['evidence_ids']})})
            self.send_json(200, {'note': note, 'events': audit_events(incident_id)})
        except auth.AuthError as error:
            self.send_json(error.status, {'error': str(error)}, {'Retry-After': str(error.retry_after)} if error.retry_after else None)
        except (ValueError, ConfigError, json.JSONDecodeError) as error:
            self.send_json(400, {'error': str(error)})


if __name__ == '__main__':
    ThreadingHTTPServer(('127.0.0.1', 8765), Handler).serve_forever()
