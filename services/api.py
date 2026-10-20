import json
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

from services.recommendations import DB_PATH, generate_recommendations, get_case_note, init_db, log_event, save_decision


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / 'src' / 'real-alerts.json'


def audit_events(incident_id):
    init_db()
    with sqlite3.connect(DB_PATH) as db:
        rows = db.execute('SELECT timestamp, event, details FROM audit_log WHERE incident_id = ? ORDER BY id', (incident_id,)).fetchall()
    events = []
    for timestamp, event, details in rows:
        detail = json.loads(details)
        events.append({'time': timestamp, 'action': event, **(detail if isinstance(detail, dict) else {})})
    return events


def saved_decisions(incident_id):
    init_db()
    with sqlite3.connect(DB_PATH) as db:
        rows = db.execute('SELECT recommendation_id, decision FROM decisions WHERE incident_id = ?', (incident_id,)).fetchall()
    return {item_id: decision.lower() for item_id, decision in rows}


def case_summary(data, incident_id):
    incident = next(item for item in data['incidents'] if item['incident_id'] == incident_id)
    return f"{len(incident['alert_ids'])} alerts from {incident['source_ip']} to {incident['destination_ip']} between {incident['window_start'].replace('T', ' ')} and {incident['window_end'].replace('T', ' ')}."


class Handler(BaseHTTPRequestHandler):
    def send_json(self, status, payload):
        body = json.dumps(payload).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', 'http://127.0.0.1:5173')
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
            else:
                raise ValueError('Unknown endpoint')
        except ValueError as error:
            self.send_json(400, {'error': str(error)})

    def do_POST(self):
        try:
            incident_id, action = self.route()
            if action != 'approval':
                raise ValueError('Unknown endpoint')
            length = int(self.headers.get('Content-Length', '0'))
            if length < 1 or length > 16384:
                raise ValueError('Invalid request size')
            request = json.loads(self.rfile.read(length))
            data = json.loads(DATA.read_text(encoding='utf-8'))
            recommendations = generate_recommendations(data, incident_id)
            decisions = request.get('decisions')
            analyst = request.get('analyst')
            ids = {item['id'] for item in recommendations}
            if not isinstance(analyst, str) or not analyst.strip() or not isinstance(decisions, dict) or set(decisions) != ids or set(decisions.values()) - {'approved', 'rejected'}:
                raise ValueError('An analyst must approve or reject every suggested check')
            init_db()
            with sqlite3.connect(DB_PATH) as db:
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
