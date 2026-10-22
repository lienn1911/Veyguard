import unittest

import numpy as np

from services.evaluate_baseline import chronological_split, count_false_positive_cases, entropy, truth
from services.evaluate_system import build_report


class BaselineEvaluationTests(unittest.TestCase):
    def test_chronological_split_keeps_minutes_separate_with_gap(self):
        keys = [('a', 'b', f'2017-07-03T09:{minute:02d}') for minute in range(50)]
        keys += [('c', 'd', '2017-07-03T09:29')]
        split = chronological_split(keys)
        minute_sets = [{keys[i][2] for i in split[name]} for name in ('train', 'calibration', 'test')]
        self.assertFalse(minute_sets[0] & minute_sets[1])
        self.assertFalse(minute_sets[1] & minute_sets[2])
        self.assertGreaterEqual(len(minute_sets[1]), 1)
        self.assertGreaterEqual(len(minute_sets[2]), 1)
        self.assertTrue(all(keys[i][2] == '2017-07-03T09:29' for i in range(len(keys) - 1, len(keys))))
        self.assertNotIn('2017-07-03T09:29', minute_sets[1])

    def test_entropy_and_mixed_truth(self):
        self.assertEqual(entropy({'80': 2}), 0)
        self.assertAlmostEqual(entropy({'80': 1, '443': 1}), 1)
        self.assertEqual(truth({'benign': 3}), 'Benign')
        self.assertEqual(truth({'benign': 1, 'ddos': 1}), 'Mixed')

    def test_false_positive_case_count_joins_nearby_minutes_by_pair(self):
        keys = [('a', 'b', '2017-07-03T09:00'), ('a', 'b', '2017-07-03T09:03'),
                ('a', 'b', '2017-07-03T09:10'), ('x', 'b', '2017-07-03T09:10')]
        self.assertEqual(count_false_positive_cases(keys, np.ones(4, dtype=bool), np.ones(4, dtype=bool)), 3)

    def test_combined_report_includes_measured_rate_sweep(self):
        baseline = {'method': 'normal-only test', 'split': {'training_groups_fitted': 10},
                    'targets': {'0.001': {'monday_holdout': {'false_positive_groups': 1}}}}
        report = build_report(baseline_report=baseline)
        self.assertEqual(report['rate_sweep']['targets'], baseline['targets'])
        self.assertIsNone(report['workflow_safety'])


if __name__ == '__main__':
    unittest.main()
