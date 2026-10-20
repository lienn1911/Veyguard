import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

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

    def test_case_note_requires_approval(self):
        rec = generate_recommendations(DATA, CASE_ID, self.db)[0]
        with self.assertRaises(ValueError):
            get_case_note(CASE_ID, self.db)
        save_decision(DATA, CASE_ID, rec['id'], 'APPROVED', 'Test Analyst', 'Needs Review', self.db)
        self.assertEqual(len(get_case_note(CASE_ID, self.db)['approved_steps']), 1)
        with closing(sqlite3.connect(self.db)) as db:
            events = [row[0] for row in db.execute('SELECT event FROM audit_log ORDER BY id')]
        self.assertIn('ANALYST_DECISION', events)

    def test_unrelated_evidence_and_closure_are_blocked(self):
        alert_id = DATA['incidents'][0]['alert_ids'][0]
        bad_evidence = validate_guardrails(DATA, CASE_ID, {'verdict': 'Needs Review', 'evidence_ids': ['ALT-UNKNOWN'], 'actions': ['REVIEW_NETWORK_FLOWS']})
        bad_action = validate_guardrails(DATA, CASE_ID, {'verdict': 'Needs Review', 'evidence_ids': [alert_id], 'actions': ['CLOSE_INCIDENT']})
        self.assertEqual(bad_evidence['status'], 'BLOCKED')
        self.assertEqual(bad_action['status'], 'BLOCKED')

    def test_attack_benign_verdict_requires_review(self):
        alert_id = DATA['incidents'][0]['alert_ids'][0]
        result = validate_guardrails(DATA, CASE_ID, {'verdict': 'Likely Benign', 'evidence_ids': [alert_id], 'actions': ['REVIEW_NETWORK_FLOWS']})
        self.assertEqual(result['status'], 'REVIEW_REQUIRED')

    def test_three_safety_failures_are_counted_separately(self):
        cases = [{'dataset_labels': ['PortScan', 'BENIGN'], 'priority': 'Low', 'recommendations': ['Close incident']}, {'dataset_labels': ['BENIGN'], 'priority': 'Low', 'recommendations': []}]
        self.assertEqual(evaluate_safety(cases), {'evaluated_cases': 2, 'attack_merged_with_benign': 1, 'attack_low_priority': 1, 'attack_closure_recommendation': 1})


if __name__ == '__main__':
    unittest.main()
