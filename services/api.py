import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from services.recommendations import DB_PATH, generate_recommendations, get_case_note, init_db, log_event, save_decision
from services.case_notes import add_note, list_notes
from services.config import load_settings
from services.data_store import Dataset
from services.triage import TriageService
from services.audit_log import AuditLog as AIAuditLog, summarize as summarize_ai_audit


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / 'src' / 'real-alerts.json'
_ai_service = None


def ai_service():
    global _ai_service
    if _ai_service is None:
        settings = load_settings()
        dataset = Dataset.load(settings.alerts_path, settings.timelines_path)
        _ai_service = TriageService(settings, dataset)
    return _ai_service


def ai_assessment(incident_id):
    service = ai_service()
    stored = service.latest(incident_id)
    latest = stored.get('latest') if stored else None
    if not latest:
        return {'status': 'pending', 'assessment': None, 'mode': service.status()['mode']}
    if latest['status'] != 'ok':
        return {'status': 'unavailable', 'assessment': None, 'mode': service.status()['mode'], 'error': latest.get('error')}
    return {'status': 'ready', 'mode': service.status()['mode'], 'assessment': {
        'verdict': latest['verdict'], 'confidence': latest['confidence'], 'summary': latest['reason'],
        'evidence_ids': latest['evidence_ids'], 'findings': latest['findings'], 'limitations': latest['limitations'],
        'requires_confirmation': latest['requires_confirmation'], 'run_id': latest['run_id'],
    }}


def audit_events(incident_id):
    init_db()
    with closing(sqlite3.connect(DB_PATH)) as db:
        rows = db.execute('SELECT timestamp, event, details FROM audit_log WHERE incident_id = ? ORDER BY id', (incident_id,)).fetchall()
    events = []
    for timestamp, event, details in rows:
        detail = json.loads(details)
        events.append({'time': timestamp, 'action': event, **(detail if isinstance(detail, dict) else {})})
    return events


def saved_decisions(incident_id):
    init_db()
    with closing(sqlite3.connect(DB_PATH)) as db:
        rows = db.execute('SELECT recommendation_id, decision FROM decisions WHERE incident_id = ?', (incident_id,)).fetchall()
    return {item_id: decision.lower() for item_id, decision in rows}


def case_summary(data, incident_id):
    incident = next(item for item in data['incidents'] if item['incident_id'] == incident_id)
    return f"{len(incident['alert_ids'])} alerts from {incident['source_ip']} to {incident['destination_ip']} between {incident['window_start'].replace('T', ' ')} and {incident['window_end'].replace('T', ' ')}."


def case_queue(data):
    init_db()
    with closing(sqlite3.connect(DB_PATH)) as db:
        db.execute('CREATE TABLE IF NOT EXISTS case_assignments (incident_id TEXT PRIMARY KEY, analyst_id TEXT NOT NULL, assigned_at TEXT NOT NULL)')
        owners = dict(db.execute('SELECT incident_id, analyst_id FROM case_assignments'))
        activity = dict(db.execute('SELECT incident_id, MAX(timestamp) FROM audit_log GROUP BY incident_id'))
        reviewed = {row[0] for row in db.execute('SELECT DISTINCT incident_id FROM decisions')}
    return {
        incident['incident_id']: {
            'status': 'Next steps reviewed' if incident['incident_id'] in reviewed else 'In review' if incident['incident_id'] in owners else 'Not reviewed',
            'owner': owners.get(incident['incident_id']),
            'last_activity': activity.get(incident['incident_id']),
        }
        for incident in data['incidents']
    }


def pending_tasks():
    init_db()
    with closing(sqlite3.connect(DB_PATH)) as db:
        rows = db.execute('''
            SELECT d.recommendation_id, d.incident_id, d.description, d.analyst_id
            FROM decisions d LEFT JOIN task_completions t
              ON t.recommendation_id = d.recommendation_id
            WHERE d.decision = 'APPROVED' AND t.recommendation_id IS NULL
            ORDER BY d.incident_id, d.recommendation_id
        ''').fetchall()
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
        db.execute('INSERT INTO audit_log (timestamp, incident_id, event, details) VALUES (?, ?, ?, ?)',
                   (timestamp, row[0], 'INVESTIGATION_STEP_COMPLETED',
                    json.dumps({'recommendation_id': recommendation_id, 'analyst_id': analyst.strip()})))
    return row[0]


class Handler(BaseHTTPRequestHandler):
    def send_json(self, status, payload):
        body = json.dumps(payload).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        origin = self.headers.get('Origin')
        if origin in {'http://127.0.0.1:5173', 'http://127.0.0.1:5174'}:
            self.send_header('Access-Control-Allow-Origin', origin)
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_json(204, {})

    def route(self):
        parts = urlsplit(self.path).path.strip('/').split('/')
        if len(parts) != 4 or parts[:2] != ['api', 'cases']:
            raise ValueError('Unknown endpoint')
        return unquote(parts[2]), parts[3]

    def do_GET(self):
        try:
            path = urlsplit(self.path)
            if path.path == '/api/audit':
                raw_limit = parse_qs(path.query).get('limit', ['100'])[0]
                limit = max(1, min(int(raw_limit), 500))
                log = AIAuditLog(load_settings().audit_path)
                self.send_json(200, {'entries': summarize_ai_audit(log.entries(limit=limit)), 'verification': log.verify()})
                return
            if path.path == '/api/audit/verify':
                self.send_json(200, AIAuditLog(load_settings().audit_path).verify())
                return
            if urlsplit(self.path).path == '/api/tasks':
                self.send_json(200, {'tasks': pending_tasks()})
                return
            if urlsplit(self.path).path == '/api/cases/queue':
                self.send_json(200, {'cases': case_queue(json.loads(DATA.read_text(encoding='utf-8')))})
                return
            incident_id, action = self.route()
            data = json.loads(DATA.read_text(encoding='utf-8'))
            if action == 'recommendations':
                recommendations = generate_recommendations(data, incident_id)
                decisions = saved_decisions(incident_id)
                note = get_case_note(incident_id) if 'approved' in decisions.values() else None
                if note:
                    note['summary'] = case_summary(data, incident_id)
                    note['approved_checks'] = [{'id': item['id'], 'text': item['description']} for item in recommendations if decisions.get(item['id']) == 'approved']
                self.send_json(200, {'incident_id': incident_id, 'checks': [{'id': item['id'], 'text': item['description'], 'evidence_ids': item['evidence_ids']} for item in recommendations], 'decisions': decisions, 'note': note})
            elif action == 'audit':
                if not any(item['incident_id'] == incident_id for item in data['incidents']):
                    raise ValueError('Unknown case')
                self.send_json(200, {'events': audit_events(incident_id)})
            elif action == 'notes':
                if not any(item['incident_id'] == incident_id for item in data['incidents']):
                    raise ValueError('Unknown case')
                self.send_json(200, {'notes': list_notes(incident_id)})
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
            task_parts = urlsplit(self.path).path.strip('/').split('/')
            if len(task_parts) == 4 and task_parts[:2] == ['api', 'tasks'] and task_parts[3] == 'complete':
                length = int(self.headers.get('Content-Length', '0'))
                if length < 1 or length > 1024:
                    raise ValueError('Invalid request size')
                request = json.loads(self.rfile.read(length))
                incident_id = complete_task(unquote(task_parts[2]), request.get('analyst'))
                self.send_json(200, {'incident_id': incident_id, 'tasks': pending_tasks()})
                return
            incident_id, action = self.route()
            if action == 'ai-assessment':
                if not any(item['incident_id'] == incident_id for item in json.loads(DATA.read_text(encoding='utf-8'))['incidents']):
                    raise ValueError('Unknown case')
                try:
                    result = ai_service().investigate(incident_id)
                    self.send_json(200 if result['status'] == 'ok' else 502, ai_assessment(incident_id))
                except Exception as error:
                    self.send_json(503, {'status': 'unavailable', 'assessment': None, 'error': {'message': str(error)}})
                return
            if action not in {'approval', 'assign', 'notes'}:
                raise ValueError('Unknown endpoint')
            length = int(self.headers.get('Content-Length', '0'))
            if length < 1 or length > 16384:
                raise ValueError('Invalid request size')
            request = json.loads(self.rfile.read(length))
            data = json.loads(DATA.read_text(encoding='utf-8'))
            if action == 'notes':
                note = add_note(data, incident_id, request.get('analyst'), request.get('evidence_id'), request.get('text'))
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
                    db.execute('INSERT INTO audit_log (timestamp, incident_id, event, details) VALUES (?, ?, ?, ?)', (timestamp, incident_id, 'CASE_ASSIGNED', json.dumps({'analyst_id': analyst.strip()})))
                self.send_json(200, {'case': case_queue(data)[incident_id]})
                return
            recommendations = generate_recommendations(data, incident_id)
            decisions = request.get('decisions')
            analyst = request.get('analyst')
            ids = {item['id'] for item in recommendations}
            if not isinstance(analyst, str) or not analyst.strip() or not isinstance(decisions, dict) or set(decisions) != ids or set(decisions.values()) - {'approved', 'rejected'}:
                raise ValueError('An analyst must approve or reject every suggested check')
            init_db()
            with closing(sqlite3.connect(DB_PATH)) as db:
                existing = db.execute('SELECT recommendation_id FROM decisions WHERE incident_id = ?', (incident_id,)).fetchall()
            if existing:
                raise ValueError('Decisions for this case have already been saved')
            for item in recommendations:
                save_decision(data, incident_id, item['id'], decisions[item['id']].upper(), analyst, 'Needs Review')
            note = None
            if 'approved' in decisions.values():
                note = get_case_note(incident_id)
                note['summary'] = case_summary(data, incident_id)
                note['approved_checks'] = [{'id': item['id'], 'text': item['description']} for item in recommendations if decisions[item['id']] == 'approved']
                log_event(incident_id, 'CASE_NOTE_DRAFTED', {'analyst_id': analyst.strip(), 'evidence_ids': sorted({e for item in recommendations if decisions[item['id']] == 'approved' for e in item['evidence_ids']})})
            self.send_json(200, {'note': note, 'events': audit_events(incident_id)})
        except (ValueError, json.JSONDecodeError) as error:
            self.send_json(400, {'error': str(error)})


if __name__ == '__main__':
    ThreadingHTTPServer(('127.0.0.1', 8765), Handler).serve_forever()
