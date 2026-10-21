"""Evaluate the one-minute detector against complete, labeled source flow files.

These are historical dataset metrics, not a live-network validation.
"""

import argparse
import csv
import io
import json
import zipfile
from collections import Counter
from pathlib import Path

from services.alerts import DEFAULT_MEMBERS, RULE_THRESHOLDS, classify_group, mark_distributed_floods, read_flow


def expected_type(labels):
    kinds = set()
    for label in labels:
        normalized = label.strip().lower()
        if normalized == 'benign':
            kinds.add('Benign')
        elif normalized == 'portscan':
            kinds.add('PortScan')
        elif normalized == 'ddos':
            kinds.add('DDoS')
        elif normalized.startswith('dos'):
            kinds.add('DoS')
        else:
            kinds.add('Other attack')
    return next(iter(kinds)) if len(kinds) == 1 else 'Mixed'


def evaluate_archive(path):
    groups = {}
    with zipfile.ZipFile(path) as archive:
        members = [name for name in archive.namelist() if name.endswith('.csv') and any(part in name for part in DEFAULT_MEMBERS)]
        if len(members) != len(DEFAULT_MEMBERS):
            raise ValueError('Expected all three CIC-IDS2017 flow CSVs; a preview cannot measure missed detections')
        for member in members:
            source_file = Path(member).name
            reader = csv.DictReader(io.TextIOWrapper(archive.open(member), encoding='utf-8-sig', newline=''))
            for row_number, row in enumerate(reader, start=2):
                flow = read_flow(row, source_file, row_number)
                key = (source_file, flow['source_ip'], flow['destination_ip'], flow['timestamp'][:16])
                group = groups.setdefault(key, {'count': 0, 'packets': 0, 'ports': set(), 'source_ports': set(), 'labels': Counter()})
                group['count'] += 1
                group['packets'] += flow['packet_count']
                group['ports'].add(flow['destination_port'])
                group['source_ports'].add(flow['source_port'])
                group['labels'][flow['dataset_label']] += 1

    matches = [{'key': key, 'type': classify_group(group)} for key, group in groups.items()]
    mark_distributed_floods(matches)
    predictions = {item['key']: item['type'] for item in matches}
    confusion = Counter()
    excluded = Counter()
    for key, group in groups.items():
        truth = expected_type(group['labels'])
        if truth in ('Mixed', 'Other attack'):
            excluded[truth] += 1
        else:
            confusion[(truth, predictions[key] or 'No alert')] += 1
    per_type = {}
    for kind in ('PortScan', 'DoS', 'DDoS'):
        tp = confusion[(kind, kind)]
        fp = sum(count for (truth, predicted), count in confusion.items() if predicted == kind and truth != kind)
        fn = sum(count for (truth, predicted), count in confusion.items() if truth == kind and predicted != kind)
        per_type[kind] = {'true_positive': tp, 'false_positive': fp, 'false_negative': fn,
                          'false_positive_from_benign': confusion[('Benign', kind)],
                          'other_attack_type_predictions': fp - confusion[('Benign', kind)],
                          'missed_without_alert': confusion[(kind, 'No alert')],
                          'precision': round(tp / (tp + fp), 4) if tp + fp else None,
                          'recall': round(tp / (tp + fn), 4) if tp + fn else None}
    attack_types = {'PortScan', 'DoS', 'DDoS'}
    attack_tp = sum(count for (truth, predicted), count in confusion.items()
                    if truth in attack_types and predicted in attack_types)
    attack_fp = sum(count for (truth, predicted), count in confusion.items()
                    if truth == 'Benign' and predicted in attack_types)
    attack_fn = sum(count for (truth, predicted), count in confusion.items()
                    if truth in attack_types and predicted == 'No alert')
    attack_detection = {
        'true_positive': attack_tp, 'false_positive': attack_fp, 'false_negative': attack_fn,
        'precision': round(attack_tp / (attack_tp + attack_fp), 4) if attack_tp + attack_fp else None,
        'recall': round(attack_tp / (attack_tp + attack_fn), 4) if attack_tp + attack_fn else None,
        'detected_by_label': {kind: sum(count for (truth, predicted), count in confusion.items()
                                        if truth == kind and predicted in attack_types)
                              for kind in ('PortScan', 'DoS', 'DDoS')},
    }
    return {'unit': 'source/destination/minute groups', 'files_evaluated': [Path(member).name for member in members],
            'rules': dict(RULE_THRESHOLDS), 'groups_scanned': len(groups),
            'excluded_ambiguous_groups': dict(excluded), 'per_type': per_type,
            'attack_detection': attack_detection,
            'confusion': [{'actual': actual, 'predicted': predicted, 'groups': count}
                          for (actual, predicted), count in sorted(confusion.items())]}


def main():
    parser = argparse.ArgumentParser(description='Report historical detection precision/recall on complete CIC-IDS2017 flow data')
    parser.add_argument('archive', type=Path)
    parser.add_argument('-o', '--output', type=Path)
    args = parser.parse_args()
    report = json.dumps(evaluate_archive(args.archive), indent=2) + '\n'
    if args.output:
        args.output.write_text(report, encoding='utf-8')
    else:
        print(report, end='')


if __name__ == '__main__':
    main()
