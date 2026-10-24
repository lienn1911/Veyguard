import copy
import json
import unittest
from pathlib import Path

from services.evaluate_grouping_gap import evaluate


class GroupingGapTests(unittest.TestCase):
    def test_sensitivity_report_preserves_input_and_baseline(self):
        data = json.loads((Path(__file__).resolve().parents[1] / 'src' / 'real-alerts.json').read_text(encoding='utf-8'))
        original = copy.deepcopy(data['alerts'])
        report = evaluate(data)
        by_gap = {item['gap_minutes']: item for item in report['results']}
        self.assertEqual(data['alerts'], original)
        self.assertEqual(by_gap[5]['case_count'], len(data['incidents']))
        self.assertEqual(by_gap[5]['baseline_cases_split'], 0)
        self.assertEqual(by_gap[5]['candidate_cases_merging_baseline'], 0)
        self.assertEqual({1, 5, 10}, set(by_gap))


if __name__ == '__main__':
    unittest.main()
