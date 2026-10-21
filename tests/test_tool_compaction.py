"""Compact model messages must retain every citable alert and its measurements."""

import unittest
from pathlib import Path

from services.data_store import Dataset
from services.tools import ToolRegistry


class ToolCompaction(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        cls.dataset = Dataset.load(root / 'src' / 'real-alerts.json', root / 'src' / 'real-timelines.json')

    def test_every_alert_remains_available_and_payload_is_bounded(self):
        for incident_id in self.dataset.incident_ids():
            with self.subTest(incident_id=incident_id):
                registry = ToolRegistry(self.dataset, incident_id)
                related = registry.execute('get_related_alerts', {'incident_id': incident_id})
                self.assertTrue(related.ok)
                expected = [self.dataset.alerts[alert_id] for alert_id in self.dataset.incidents[incident_id]['alert_ids']]
                self.assertEqual([item['alert_id'] for item in related.data['alerts']],
                                 [item['alert_id'] for item in expected])
                self.assertEqual([item['flow_count'] for item in related.data['alerts']],
                                 [item['flow_count'] for item in expected])
                self.assertEqual([item['rule_basis'] for item in related.data['alerts']],
                                 [item['rule_basis'] for item in expected])
                self.assertLess(len(related.as_text()), 8000)
                statistics = registry.execute('get_incident_statistics', {'incident_id': incident_id})
                self.assertEqual(statistics.data['group_totals']['flows'],
                                 self.dataset.incidents[incident_id]['flow_count'])
                self.assertNotIn('alert_totals', statistics.data)


if __name__ == '__main__':
    unittest.main()
