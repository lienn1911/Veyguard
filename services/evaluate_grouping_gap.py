"""Compare deterministic case grouping windows without changing the demo queue."""

import argparse
import copy
import json
from collections import Counter
from pathlib import Path

from .alerts import INCIDENT_GAP_MINUTES, group_alerts


def evaluate(data, gaps=(1, INCIDENT_GAP_MINUTES, 10)):
    alerts = data['alerts']
    partitions = {gap: group_alerts(copy.deepcopy(alerts), gap_minutes=gap) for gap in gaps}
    baseline = partitions[INCIDENT_GAP_MINUTES]
    baseline_by_alert = {alert_id: case['incident_id'] for case in baseline for alert_id in case['alert_ids']}
    results = []
    for gap, cases in partitions.items():
        by_type = Counter(case['type'] for case in cases)
        split_baseline = sum(
            len({case['incident_id'] for case in cases if set(case['alert_ids']) & set(base['alert_ids'])}) > 1
            for base in baseline
        )
        merged_baseline = sum(
            len({baseline_by_alert[alert_id] for alert_id in case['alert_ids']}) > 1
            for case in cases
        )
        results.append({
            'gap_minutes': gap,
            'case_count': len(cases),
            'cases_by_rule': dict(sorted(by_type.items())),
            'baseline_cases_split': split_baseline,
            'candidate_cases_merging_baseline': merged_baseline,
        })
    return {
        'source': data.get('provenance', {}).get('dataset'),
        'alert_count': len(alerts),
        'baseline_gap_minutes': INCIDENT_GAP_MINUTES,
        'results': results,
        'limitation': 'This is a grouping sensitivity check, not proof of correct incident boundaries. Dataset labels do not identify real campaign boundaries.',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('alerts_json', type=Path)
    parser.add_argument('-o', '--output', type=Path)
    args = parser.parse_args()
    result = evaluate(json.loads(args.alerts_json.read_text(encoding='utf-8')))
    output = json.dumps(result, indent=2) + '\n'
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output, encoding='utf-8')
    else:
        print(output, end='')


if __name__ == '__main__':
    main()
