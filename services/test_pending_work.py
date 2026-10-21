import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from services.alerts import group_alerts
from services.audit_log import AuditLog
from services.data_store import Dataset
from services.evaluate_system import build_report, chronological_minute_split
from services.store import TriageStore
from services.triage import TriageService
from services.validation import check_numeric_claims


DATA = json.loads((Path(__file__).resolve().parents[1] / 'src' / 'real-alerts.json').read_text(encoding='utf-8'))


def alert(alert_id, kind, source, target, minute):
    return {'alert_id': alert_id, 'type': kind, 'source_file': 'capture.csv',
            'source_ip': source, 'destination_ip': target, 'timestamp': f'2023-01-01T10:{minute:02d}:00',
            'evidence_sample_ids': [], 'flow_count': 10}


class PendingWorkTests(unittest.TestCase):
    def test_type_specific_grouping_and_gap(self):
        items = [alert('A', 'PortScan', 's1', 'd1', 0), alert('B', 'PortScan', 's1', 'd2', 4),
                 alert('C', 'PortScan', 's1', 'd3', 10), alert('D', 'DoS', 's1', 'd1', 0),
                 alert('E', 'DoS', 's2', 'd1', 3), alert('F', 'DDoS', 's3', 'd1', 3)]
        cases = group_alerts(items)
        grouped = {frozenset(case['alert_ids']): case for case in cases}
        self.assertEqual(grouped[frozenset({'A', 'B'})]['destination_ip'], 'Multiple destinations')
        self.assertEqual(grouped[frozenset({'D', 'E'})]['source_ip'], 'Multiple sources')
        self.assertIn(frozenset({'C'}), grouped)
        self.assertIn(frozenset({'F'}), grouped)
        self.assertIn(grouped[frozenset({'D', 'E'})]['incident_id'],
                      grouped[frozenset({'A', 'B'})]['related_incident_ids'])

    def test_ai_numeric_claim_requires_stored_statistic(self):
        dataset = Dataset(DATA)
        case_id = DATA['incidents'][0]['incident_id']
        canonical = dataset.canonical_statistic_numbers(case_id)
        self.assertTrue(check_numeric_claims('999999 flows were observed', {999999}, canonical))
        real = next(item['flow_count'] for item in DATA['alerts'] if item['incident_id'] == case_id)
        self.assertFalse(check_numeric_claims(f'{real} flows were observed', {float(real)}, canonical))

    def test_audit_is_shared_append_only_and_verifiable(self):
        with tempfile.TemporaryDirectory() as folder:
            log = AuditLog(Path(folder) / 'audit.db')
            log.append('triage.started', incident_id='INC-ONE')
            log.append('ANALYST_DECISION', incident_id='INC-ONE', actor='analyst:test', payload={'decision': 'APPROVED'})
            self.assertEqual([item['event'] for item in log.entries()], ['triage.started', 'ANALYST_DECISION'])
            self.assertTrue(log.verify()['ok'])
            with closing(sqlite3.connect(log.path)) as db:
                with self.assertRaises(sqlite3.DatabaseError):
                    db.execute("UPDATE audit_events SET event = 'changed' WHERE seq = 1")

    def test_old_ai_and_analyst_events_migrate_once(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            legacy = root / 'audit' / 'triage-audit.jsonl'
            legacy.parent.mkdir()
            legacy.write_text(json.dumps({'event_id': 'AUD-OLD', 'ts': '2023-01-01T00:00:00Z',
                                          'event': 'triage.started', 'incident_id': 'INC-ONE',
                                          'actor': 'system:triage-agent', 'payload': {}}) + '\n', encoding='utf-8')
            db_path = root / 'audit.db'
            with closing(sqlite3.connect(db_path)) as db, db:
                db.execute('CREATE TABLE audit_log (id INTEGER PRIMARY KEY, timestamp TEXT, incident_id TEXT, event TEXT, details TEXT)')
                db.execute('INSERT INTO audit_log VALUES (1, ?, ?, ?, ?)',
                           ('2023-01-01T00:01:00Z', 'INC-ONE', 'ANALYST_DECISION', '{"analyst_id":"alice"}'))
            log = AuditLog(legacy)
            self.assertEqual([row['event'] for row in log.entries()], ['triage.started', 'ANALYST_DECISION'])
            self.assertEqual(len(log.entries()), 2)
            self.assertTrue(log.verify()['ok'])

    def test_likely_benign_confirmation_requires_reason(self):
        with tempfile.TemporaryDirectory() as folder:
            service = object.__new__(TriageService)
            service.store = TriageStore(Path(folder) / 'state.json')
            service.audit = AuditLog(Path(folder) / 'audit.db')
            case_id = DATA['incidents'][0]['incident_id']
            service.store.save_run({'incident_id': case_id, 'run_id': 'TRG-TEST', 'proposal': {'verdict': 'Likely Benign'},
                                    'requires_confirmation': True})
            with self.assertRaisesRegex(ValueError, 'written reason'):
                service.decide(case_id, decision='confirmed', analyst='analyst', note='')
            service.decide(case_id, decision='confirmed', analyst='analyst', note='Checked linked evidence')
            with self.assertRaisesRegex(ValueError, 'already has'):
                service.decide(case_id, decision='rejected', analyst='analyst', note='Changed mind')

    def test_evaluation_skeleton_does_not_invent_rate_sweep(self):
        report = build_report({'attack_detection': {'recall': 0.4, 'true_positive': 4,
                                                      'false_negative': 6, 'false_positive': 1}}, [])
        self.assertEqual(report['rule_detection']['recall'], 0.4)
        self.assertIn('pending', report['rate_sweep']['status'])
        self.assertEqual(report['workflow_safety']['evaluated_cases'], 0)

    def test_chronological_split_keeps_minute_groups_together(self):
        groups = [{'timestamp': f'2023-01-01T10:{minute:02d}:00', 'source': source}
                  for minute in range(5) for source in ('s1', 's2')]
        split = chronological_minute_split(groups)
        minute_sets = [{item['timestamp'][:16] for item in split[key]}
                       for key in ('train', 'calibration', 'test')]
        self.assertTrue(all(minute_sets))
        self.assertFalse(minute_sets[0] & minute_sets[1] or minute_sets[1] & minute_sets[2] or minute_sets[0] & minute_sets[2])


if __name__ == '__main__':
    unittest.main()
