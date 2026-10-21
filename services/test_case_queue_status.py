"""Review status follows persisted analyst actions, not the AI verdict alone."""

import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from services import api, recommendations
from services.unified_audit import append


class CaseQueueStatusTests(unittest.TestCase):
    def test_review_status_transitions(self):
        data = json.loads(api.DATA.read_text(encoding='utf-8'))
        incident_id = data['incidents'][0]['incident_id']
        fake_triage = SimpleNamespace(
            settings=SimpleNamespace(is_mock=False, provider='groq', model='test-model'),
            latest=lambda _id: {'latest': {'status': 'ok', 'provider': 'groq', 'model': 'test-model'},
                                'decision': {'status': 'pending'}},
        )
        with tempfile.TemporaryDirectory(dir=api.ROOT) as folder:
            db_path = Path(folder) / 'reviews.db'
            with patch.object(api, 'DB_PATH', db_path), patch.object(api, 'init_db', lambda: recommendations.init_db(db_path)), patch.object(api, 'ai_service', lambda: fake_triage):
                self.assertEqual(api.case_queue(data)[incident_id]['status'], 'AI ready for review')
                fake_triage.latest = lambda _id: {}
                append(db_path, 'ANALYST_NOTE_ADDED', incident_id=incident_id,
                       actor='analyst:Analyst', payload={'note_id': 1})
                self.assertEqual(api.case_queue(data)[incident_id]['status'], 'In review')
                fake_triage.latest = lambda _id: {'latest': {'status': 'ok', 'provider': 'groq', 'model': 'test-model'},
                                                  'decision': {'status': 'pending'}}
                self.assertEqual(api.case_queue(data)[incident_id]['status'], 'In review')
                with closing(sqlite3.connect(db_path)) as db, db:
                    db.execute('INSERT INTO case_assignments VALUES (?, ?, ?)', (incident_id, 'Analyst', 'now'))
                fake_triage.latest = lambda _id: {'decision': {'status': 'confirmed'}}
                self.assertEqual(api.case_queue(data)[incident_id]['status'], 'AI assessment confirmed')

                checks = recommendations.generate_recommendations(data, incident_id)
                with closing(sqlite3.connect(db_path)) as db, db:
                    for check in checks:
                        db.execute('INSERT INTO decisions VALUES (?, ?, ?, ?, ?, ?, ?)',
                                   (check['id'], incident_id, check['action'], check['description'],
                                    json.dumps(check['evidence_ids']), 'APPROVED', 'Analyst'))
                item = api.case_queue(data)[incident_id]
                self.assertEqual(item['status'], 'Next steps approved')
                self.assertTrue(item['review_complete'])

                with closing(sqlite3.connect(db_path)) as db, db:
                    for check in checks:
                        db.execute('INSERT INTO task_completions VALUES (?, ?, ?)',
                                   (check['id'], 'Analyst', 'now'))
                self.assertEqual(api.case_queue(data)[incident_id]['status'], 'Approved steps completed')


if __name__ == '__main__':
    unittest.main()
