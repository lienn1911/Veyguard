"""Executable checks for grouping, analyst decisions, and audit persistence."""

import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from services.alerts import group_alerts
from services.audit_log import AuditLog
from services.unified_audit import initialize
from services.store import TriageStore
from services.triage import TriageService
from services.recommendations import generate_recommendations, get_case_note, save_decision


def alert(number, kind, source, destination, minute=0):
    return {
        'alert_id': f'ALT-{number}', 'type': kind,
        'source_file': 'sample.csv', 'source_ip': source,
        'destination_ip': destination,
        'timestamp': f'2017-07-07T15:{minute:02d}:00',
        'evidence_sample_ids': [f'FLOW-{number}'], 'flow_count': 10,
    }


class GroupingContracts(unittest.TestCase):
    def test_three_sources_one_ddos_destination_remain_separate_cases(self):
        incidents = group_alerts([
            alert(1, 'DDoS', '10.0.0.1', '192.0.2.1'),
            alert(2, 'DDoS', '10.0.0.2', '192.0.2.1', 1),
            alert(3, 'DDoS', '10.0.0.3', '192.0.2.1', 2),
        ])
        self.assertEqual(len(incidents), 3)
        self.assertEqual({item['source_ip'] for item in incidents}, {'10.0.0.1', '10.0.0.2', '10.0.0.3'})
        self.assertTrue(all(len(item['alert_ids']) == 1 for item in incidents))

    def test_one_scanner_two_destinations_remain_separate_cases(self):
        incidents = group_alerts([
            alert(1, 'PortScan', '10.0.0.1', '192.0.2.1'),
            alert(2, 'PortScan', '10.0.0.1', '192.0.2.2', 1),
        ])
        self.assertEqual(len(incidents), 2)
        self.assertEqual({item['destination_ip'] for item in incidents}, {'192.0.2.1', '192.0.2.2'})
        self.assertTrue(all(len(item['alert_ids']) == 1 for item in incidents))


class AuditContracts(unittest.TestCase):
    def test_database_rejects_update_and_delete(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as directory:
            log = AuditLog(Path(directory) / 'legacy.jsonl')
            log.append('triage.started', incident_id='INC-1')
            with closing(sqlite3.connect(log.path)) as db:
                for statement in (
                    "UPDATE audit_events SET event = 'changed' WHERE seq = 1",
                    'DELETE FROM audit_events WHERE seq = 1',
                ):
                    with self.assertRaisesRegex(sqlite3.IntegrityError, 'append-only'):
                        db.execute(statement)
            self.assertTrue(log.verify()['ok'])

    def test_legacy_import_is_idempotent_and_preserves_origin_and_time(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as directory:
            root = Path(directory)
            db_path = root / 'audit.db'
            legacy_path = root / 'old.jsonl'
            legacy_path.write_text(json.dumps({
                'ts': '2017-07-07T15:00:00Z', 'event': 'triage.started',
                'incident_id': 'INC-1', 'actor': 'system:old-agent',
                'payload': {'source': 'legacy'},
            }) + '\n', encoding='utf-8')
            initialize(db_path, legacy_path)
            initialize(db_path, legacy_path)
            with closing(sqlite3.connect(db_path)) as db:
                rows = db.execute('SELECT ts, actor, source_key FROM audit_events').fetchall()
            self.assertEqual(rows, [('2017-07-07T15:00:00Z', 'system:old-agent', 'jsonl:1')])


class AnalystContracts(unittest.TestCase):
    def test_likely_benign_attack_requires_reason_and_preserves_open_case(self):
        scratch = Path(__file__).resolve().parents[1] / 'data' / 'test-temp'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            root = Path(directory)
            service = object.__new__(TriageService)
            from services.data_store import Dataset
            service.dataset = Dataset({'incidents':[{'incident_id':'INC-1'}], 'alerts':[{'incident_id':'INC-1','alert_id':'A'}]})
            service.store = TriageStore(root / 'state.json')
            service.audit = AuditLog(root / 'audit.db')
            service.store.save_run({
                'incident_id': 'INC-1', 'run_id': 'RUN-1',
                'requires_confirmation': True,
                'proposal': {'verdict': 'Likely Benign'},
            })
            with self.assertRaisesRegex(ValueError, 'written reason'):
                service.decide('INC-1', decision='confirmed', analyst='ana', note='  ')
            self.assertEqual(service.store.get('INC-1')['decision']['status'], 'pending')
            self.assertEqual(service.audit.entries(), [])

            stored = service.decide('INC-1', decision='confirmed', analyst='ana',
                                    note='Checked the linked evidence.')
            self.assertEqual(stored['decision']['status'], 'confirmed')
            self.assertEqual(stored['latest']['proposal']['verdict'], 'Likely Benign')
            self.assertNotIn('closed', stored)
            self.assertNotIn('priority', stored)
            events = service.audit.entries()
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]['event'], 'analyst.decision')
            self.assertEqual(events[0]['payload']['note'], 'Checked the linked evidence.')

    def test_approved_check_is_audited_and_produces_draft(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as directory:
            db_path = Path(directory) / 'audit.db'
            data = json.loads((Path(__file__).resolve().parents[1] / 'src' / 'real-alerts.json').read_text(encoding='utf-8'))
            incident_id = data['incidents'][0]['incident_id']
            recommendation = generate_recommendations(data, incident_id, db_path)[0]
            saved = save_decision(data, incident_id, recommendation['id'], 'APPROVED',
                                  'ana', 'Needs Review', db_path)
            self.assertEqual(saved['decision'], 'APPROVED')
            note = get_case_note(incident_id, db_path)
            self.assertEqual(note['status'], 'DRAFT')
            self.assertEqual(len(note['approved_steps']), 1)
            events = AuditLog(db_path).entries(incident_id=incident_id)
            self.assertTrue(any(event['event'] == 'ANALYST_DECISION' and
                                event['payload']['decision'] == 'APPROVED' for event in events))


if __name__ == '__main__':
    unittest.main()
