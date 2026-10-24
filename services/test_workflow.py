import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from services.api import complete_task, pending_tasks
from services.case_notes import add_note, list_notes
from services.guardrails import evaluate_safety, validate_guardrails
from services.recommendations import generate_recommendations, get_case_note, save_decision


DATA = json.loads((Path(__file__).resolve().parents[1] / 'src' / 'real-alerts.json').read_text(encoding='utf-8'))
CASE_ID = DATA['incidents'][0]['incident_id']


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.db = Path(self.folder.name) / 'audit.db'

    def tearDown(self):
        self.folder.cleanup()

    def test_recommendations_are_read_only_and_evidence_linked(self):
        recs = generate_recommendations(DATA, CASE_ID, self.db)
        allowed = set(DATA['incidents'][0]['alert_ids'] + DATA['incidents'][0]['evidence_sample_ids'])
        self.assertTrue(recs)
        self.assertTrue(all(set(rec['evidence_ids']) <= allowed for rec in recs))
        self.assertTrue(all(rec['action'].startswith(('REVIEW_', 'CHECK_', 'ESCALATE_')) for rec in recs))
        by_action = {rec['action']: rec for rec in recs}
        self.assertEqual(by_action['REVIEW_NETWORK_FLOWS']['evidence_ids'], DATA['incidents'][0]['evidence_sample_ids'])
        self.assertEqual(by_action['CHECK_RELATED_ALERTS']['evidence_ids'], DATA['incidents'][0]['alert_ids'])
        self.assertFalse(self.db.exists())

    def test_case_note_requires_approval(self):
        rec = generate_recommendations(DATA, CASE_ID, self.db)[0]
        with self.assertRaises(ValueError):
            get_case_note(CASE_ID, self.db)
        save_decision(DATA, CASE_ID, rec['id'], 'APPROVED', 'Test Analyst', 'Needs Review', self.db)
        self.assertEqual(len(get_case_note(CASE_ID, self.db)['approved_steps']), 1)
        with closing(sqlite3.connect(self.db)) as db:
            events = [row[0] for row in db.execute('SELECT event FROM audit_events ORDER BY seq')]
        self.assertIn('ANALYST_DECISION', events)

    def test_decision_remark_is_saved_with_audit_event(self):
        rec = generate_recommendations(DATA, CASE_ID, self.db)[0]
        save_decision(DATA, CASE_ID, rec['id'], 'REJECTED', 'Test Analyst', 'Needs Review', self.db, remark='Reviewed the linked alerts')
        with closing(sqlite3.connect(self.db)) as db:
            self.assertEqual(db.execute('SELECT remark FROM decisions WHERE recommendation_id = ?', (rec['id'],)).fetchone()[0], 'Reviewed the linked alerts')
            details = db.execute("SELECT payload FROM audit_events WHERE event = 'ANALYST_DECISION'").fetchone()[0]
        self.assertIn('Reviewed the linked alerts', details)

    def test_approved_step_becomes_pending_task_until_analyst_completes_it(self):
        rec = generate_recommendations(DATA, CASE_ID, self.db)[0]
        save_decision(DATA, CASE_ID, rec['id'], 'APPROVED', 'Test Analyst', 'Needs Review', self.db)
        with patch('services.api.DB_PATH', self.db):
            self.assertEqual([task['id'] for task in pending_tasks()], [rec['id']])
            self.assertEqual(complete_task(rec['id'], 'Test Analyst'), CASE_ID)
            self.assertEqual(pending_tasks(), [])
            with self.assertRaisesRegex(ValueError, 'already completed'):
                complete_task(rec['id'], 'Test Analyst')
        with closing(sqlite3.connect(self.db)) as db:
            events = [row[0] for row in db.execute('SELECT event FROM audit_events ORDER BY seq')]
        self.assertIn('INVESTIGATION_STEP_COMPLETED', events)

    def test_case_note_links_only_its_own_evidence_and_is_audited(self):
        evidence_id = DATA['incidents'][0]['alert_ids'][0]
        with self.assertRaisesRegex(ValueError, 'Select evidence'):
            add_note(DATA, CASE_ID, 'Test Analyst', 'ALT-UNKNOWN', 'Observed activity', self.db)
        note = add_note(DATA, CASE_ID, 'Test Analyst', evidence_id, 'Observed activity', self.db)
        self.assertEqual(list_notes(CASE_ID, self.db), [note])
        with closing(sqlite3.connect(self.db)) as db:
            events = [row[0] for row in db.execute('SELECT event FROM audit_events ORDER BY seq')]
        self.assertEqual(events, ['ANALYST_NOTE_ADDED'])

    def test_unrelated_evidence_and_closure_are_blocked(self):
        alert_id = DATA['incidents'][0]['alert_ids'][0]
        bad_evidence = validate_guardrails(DATA, CASE_ID, {'verdict': 'Needs Review', 'evidence_ids': ['ALT-UNKNOWN'], 'actions': ['REVIEW_NETWORK_FLOWS']})
        bad_action = validate_guardrails(DATA, CASE_ID, {'verdict': 'Needs Review', 'evidence_ids': [alert_id], 'actions': ['CLOSE_INCIDENT']})
        self.assertEqual(bad_evidence['status'], 'BLOCKED')
        self.assertEqual(bad_action['status'], 'BLOCKED')

    def test_attack_benign_verdict_requires_review(self):
        attack = next(item for item in DATA['incidents'] if item['type'] == 'BruteForce')
        alert_id = attack['alert_ids'][0]
        result = validate_guardrails(DATA, attack['incident_id'], {'verdict': 'Likely Benign', 'evidence_ids': [alert_id], 'actions': ['REVIEW_NETWORK_FLOWS']})
        self.assertEqual(result['status'], 'REVIEW_REQUIRED')

    def test_three_safety_failures_are_counted_separately(self):
        cases = [{'dataset_labels': ['PortScan', 'BENIGN'], 'priority': 'Low', 'recommendations': ['Close incident']}, {'dataset_labels': ['BENIGN'], 'priority': 'Low', 'recommendations': []}]
        self.assertEqual(evaluate_safety(cases), {'evaluated_cases': 2, 'attack_merged_with_benign': 1, 'attack_low_priority': 1, 'attack_closure_recommendation': 1})


if __name__ == '__main__':
    unittest.main()
