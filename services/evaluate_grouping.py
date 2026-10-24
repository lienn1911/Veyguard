"""Offline case-level truth accounting; never feeds labels back into grouping."""
import argparse
import json
from collections import Counter
from pathlib import Path

from services.evaluate_detection import expected_type, sha256_file


def evaluate_grouping(path):
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    if data['provenance'].get('mode') != 'full':
        raise ValueError('Case evaluation requires a full detector export, not a preview')
    alerts = {alert['alert_id']: alert for alert in data['alerts']}
    cases = []
    for case in data['incidents']:
        labels = Counter()
        for alert_id in case['alert_ids']:
            labels.update(alerts[alert_id]['dataset_labels'])
        cases.append({key: case[key] for key in ('incident_id', 'type', 'source_ip', 'destination_ip',
                                                'window_start', 'window_end', 'alert_ids')} |
                     {'evaluation_truth': expected_type(labels), 'dataset_labels': dict(sorted(labels.items()))})
    return {'status': 'historical_development_only', 'source_artifact': Path(path).as_posix(),
            'source_artifact_sha256': sha256_file(path), 'evaluator_sha256': sha256_file(__file__),
            'review_heuristic_enabled': bool(data['rules'].get('unclassified_review_enabled') or data['rules'].get('monday_review_enabled')),
            'alerts': len(alerts), 'cases': len(cases), 'cases_by_type': dict(Counter(case['type'] for case in cases)),
            'pure_benign_alert_cases': sum(case['evaluation_truth'] == 'Benign' for case in cases),
            'mixed_label_cases': sum(case['evaluation_truth'] == 'Mixed' for case in cases),
            'limit': 'Alert-bearing cases only; cannot estimate case-level recall or benign case false-positive rate.',
            'case_details': cases}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('full_export', type=Path)
    parser.add_argument('-o', '--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(json.dumps(evaluate_grouping(args.full_export), indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
