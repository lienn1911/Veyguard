"""Combine detector recall and three independent workflow safety counters.

This report intentionally leaves rate-sweep results pending until out-of-sample
scores and group-level truth are available. It never invents model metrics.
"""

import argparse
import json
from pathlib import Path

from services.guardrails import evaluate_safety


def chronological_minute_split(groups, train_fraction=0.6, calibration_fraction=0.2):
    """Split ordered minute groups without placing one minute in two partitions."""
    if not 0 < train_fraction < 1 or not 0 < calibration_fraction < 1 or train_fraction + calibration_fraction >= 1:
        raise ValueError('Train and calibration fractions must leave a test partition')
    minutes = sorted({item['timestamp'][:16] for item in groups})
    if len(minutes) < 3:
        raise ValueError('At least three distinct minutes are required')
    train_end = max(1, min(len(minutes) - 2, int(len(minutes) * train_fraction)))
    calibration_end = max(train_end + 1, min(len(minutes) - 1, int(len(minutes) * (train_fraction + calibration_fraction))))
    training = set(minutes[:train_end])
    calibration = set(minutes[train_end:calibration_end])
    return {
        'train': [item for item in groups if item['timestamp'][:16] in training],
        'calibration': [item for item in groups if item['timestamp'][:16] in calibration],
        'test': [item for item in groups if item['timestamp'][:16] not in training | calibration],
    }


def build_report(detector_report=None, evaluation_cases=None, baseline_report=None):
    result = {
        'calibration_unit': 'source IP / destination IP / minute group',
        'case_false_positive_unit': 'case with only Benign-labeled groups',
        'target_false_positive_rates': [0.0001, 0.001, 0.01],
        'rate_sweep': {'status': 'pending independent normal training, calibration and test data'},
        'rule_detection': None,
        'workflow_safety': None,
    }
    if detector_report is not None:
        item = detector_report['attack_detection']
        result['rule_detection'] = {
            'unit': detector_report.get('unit', 'source/destination/minute groups'),
            'recall': item.get('recall'),
            'true_positive': item.get('true_positive'),
            'false_negative': item.get('false_negative'),
            'false_positive': item.get('false_positive'),
        }
    if evaluation_cases is not None:
        result['workflow_safety'] = evaluate_safety(evaluation_cases)
    if baseline_report is not None:
        result['rate_sweep'] = {
            'status': 'offline normal-only baseline evaluated; not deployed as the detector',
            'method': baseline_report['method'],
            'split': baseline_report['split'],
            'targets': baseline_report['targets'],
        }
    return result


def main():
    parser = argparse.ArgumentParser(description='Summarize rule recall and three workflow safety indicators')
    parser.add_argument('--detector-report', type=Path)
    parser.add_argument('--baseline-report', type=Path, help='Output from services.evaluate_baseline')
    parser.add_argument('--cases', type=Path, help='JSON array of reviewed evaluation cases')
    parser.add_argument('-o', '--output', type=Path)
    args = parser.parse_args()
    detector = json.loads(args.detector_report.read_text(encoding='utf-8')) if args.detector_report else None
    baseline = json.loads(args.baseline_report.read_text(encoding='utf-8')) if args.baseline_report else None
    cases = json.loads(args.cases.read_text(encoding='utf-8')) if args.cases else None
    if cases is not None and not isinstance(cases, list):
        parser.error('--cases must contain a JSON array')
    report = json.dumps(build_report(detector, cases, baseline), indent=2) + '\n'
    if args.output:
        args.output.write_text(report, encoding='utf-8')
    else:
        print(report, end='')


if __name__ == '__main__':
    main()
