"""Evaluate the one-minute detector against complete, labeled source flow files.

These are historical dataset metrics, not a live-network validation.
"""

import argparse
import csv
import io
import hashlib
import platform
import json
import zipfile
from collections import Counter
from pathlib import Path

from services.alerts import DEFAULT_MEMBERS, RULE_THRESHOLDS, classify_group, needs_review_candidate, read_flow, select_archive_members, DISPLAY_ATTACK_TYPES


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
        elif normalized in ('ftp-patator', 'ssh-patator'):
            kinds.add('BruteForce')
        else:
            kinds.add('Other attack')
    return next(iter(kinds)) if len(kinds) == 1 else 'Mixed'


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def detector_hash():
    return sha256_file(Path(__file__).with_name('alerts.py'))


def validate_holdout(manifest, archive, archive_hash):
    """Validate a predeclared external holdout; never manufacture independence by splitting tuned data."""
    if manifest.get('purpose') != 'external_holdout' or not manifest.get('frozen_at'):
        raise ValueError('Holdout requires purpose=external_holdout and frozen_at')
    if manifest.get('detector_sha256') != detector_hash():
        raise ValueError('Detector differs from frozen holdout manifest')
    development = manifest.get('development_archive_sha256', [])
    if not development or archive_hash in development:
        raise ValueError('Declare development archive hashes; holdout must differ')
    if archive_hash != manifest.get('archive_sha256'):
        raise ValueError('Holdout archive hash mismatch')
    members = manifest.get('members', {})
    development_members = set(manifest.get('development_member_sha256', []))
    if not members or not development_members:
        raise ValueError('Declare holdout members and development member hashes')
    for name, expected_hash in members.items():
        with archive.open(name) as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        if digest != expected_hash or digest in development_members:
            raise ValueError(f'Changed or development-overlapping holdout member: {name}')
    return sorted(members)


def evaluate_archive(path, manifest=None):
    groups = {}
    archive_hash = sha256_file(path)
    with zipfile.ZipFile(path) as archive:
        members = validate_holdout(manifest, archive, archive_hash) if manifest else select_archive_members(archive)
        if not manifest and len(members) != len(DEFAULT_MEMBERS):
            raise ValueError('Expected Monday, Tuesday, Wednesday, and Friday PortScan flow CSVs; a preview cannot measure missed detections')
        for member in members:
            source_file = member
            reader = csv.DictReader(io.TextIOWrapper(archive.open(member), encoding='utf-8-sig', newline=''))
            for row_number, row in enumerate(reader, start=2):
                flow = read_flow(row, source_file, row_number)
                key = (source_file, flow['source_ip'], flow['destination_ip'], flow['timestamp'][:16])
                group = groups.setdefault(key, {'count': 0, 'packets': 0, 'ports': set(),
                                                'source_ports': set(), 'port_flow_counts': Counter(), 'labels': Counter()})
                group['count'] += 1
                group['packets'] += flow['packet_count']
                group['ports'].add(flow['destination_port'])
                group['port_flow_counts'][flow['destination_port']] += 1
                group['source_ports'].add(flow['source_port'])
                group['labels'][flow['dataset_label']] += 1

    matches = [{'key': key, 'type': classify_group(group)} for key, group in groups.items()]
    predictions = {item['key']: item['type'] for item in matches}
    confusion = Counter()
    excluded = Counter()
    errors = []
    excluded_predictions = Counter()
    for key, group in groups.items():
        truth = expected_type(group['labels'])
        if truth not in (*DISPLAY_ATTACK_TYPES, 'Benign'):
            excluded[truth] += 1
            excluded_predictions[predictions[key] or 'No alert'] += 1
        else:
            predicted = predictions[key] or 'No alert'
            confusion[(truth, predicted)] += 1
            if predicted != truth and not (truth == 'Benign' and predicted == 'No alert'):
                errors.append({'source_file': key[0], 'source_ip': key[1], 'destination_ip': key[2],
                               'minute': key[3], 'actual': truth, 'predicted': predicted,
                               'labels': dict(sorted(group['labels'].items()))})
    per_type = {}
    for kind in ('PortScan', 'DoS', 'BruteForce'):
        tp = confusion[(kind, kind)]
        fp = sum(count for (truth, predicted), count in confusion.items() if predicted == kind and truth != kind)
        fn = sum(count for (truth, predicted), count in confusion.items() if truth == kind and predicted != kind)
        per_type[kind] = {'true_positive': tp, 'false_positive': fp, 'false_negative': fn,
                          'false_positive_from_benign': confusion[('Benign', kind)],
                          'other_attack_type_predictions': fp - confusion[('Benign', kind)],
                          'missed_without_alert': confusion[(kind, 'No alert')],
                          'precision': round(tp / (tp + fp), 4) if tp + fp else None,
                          'recall': round(tp / (tp + fn), 4) if tp + fn else None}
    attack_types = {'PortScan', 'DoS', 'BruteForce'}
    attack_tp = sum(count for (truth, predicted), count in confusion.items()
                    if truth in attack_types and predicted in attack_types)
    attack_fp = sum(count for (truth, predicted), count in confusion.items()
                    if truth == 'Benign' and predicted in attack_types)
    attack_fn = sum(count for (truth, predicted), count in confusion.items()
                    if truth in attack_types and predicted == 'No alert')
    tn = confusion[('Benign', 'No alert')]
    attack_detection = {
        'true_negative': tn,
        'benign_groups': tn + attack_fp,
        'false_positive_rate': round(attack_fp / (attack_fp + tn), 10) if attack_fp + tn else None,
        'true_positive': attack_tp, 'false_positive': attack_fp, 'false_negative': attack_fn,
        'precision': round(attack_tp / (attack_tp + attack_fp), 4) if attack_tp + attack_fp else None,
        'recall': round(attack_tp / (attack_tp + attack_fn), 4) if attack_tp + attack_fn else None,
        'detected_by_label': {kind: sum(count for (truth, predicted), count in confusion.items()
                                        if truth == kind and predicted in attack_types)
                              for kind in ('PortScan', 'DoS', 'BruteForce')},
    }
    return {'schema_version': 2,
            'scope': list(DISPLAY_ATTACK_TYPES),
            'evaluation_status': 'external_holdout_manifest_verified' if manifest else 'historical_development_only',
            'provenance': {'archive_sha256': archive_hash, 'detector_sha256': detector_hash(),
                           'evaluator_sha256': sha256_file(__file__), 'python': platform.python_version(),
                           'manifest': manifest, 'independence_limit': 'Hashes verify declared separation, not prior human exposure or duplicate traffic.'},
            'errors': sorted(errors, key=lambda row: (row['source_file'], row['minute'], row['source_ip'], row['destination_ip'])),
            'excluded_predictions': dict(sorted(excluded_predictions.items())),
            'unit': 'source/destination/minute groups', 'files_evaluated': [Path(member).name for member in members],
            'rules': dict(RULE_THRESHOLDS), 'groups_scanned': len(groups),
            'monday_review_candidates': sum(1 for key, group in groups.items()
                                            if key[0].startswith('Monday-') and not classify_group(group)
                                            and needs_review_candidate(group)),
            'excluded_ambiguous_groups': dict(sorted(excluded.items())), 'per_type': per_type,
            'attack_detection': attack_detection,
            'confusion': [{'actual': actual, 'predicted': predicted, 'groups': count}
                          for (actual, predicted), count in sorted(confusion.items())]}


def main():
    parser = argparse.ArgumentParser(description='Report historical detection precision/recall on complete CIC-IDS2017 flow data')
    parser.add_argument('archive', type=Path)
    parser.add_argument('--holdout-manifest', type=Path, help='Predeclared external holdout with frozen detector and input hashes')
    parser.add_argument('-o', '--output', type=Path)
    args = parser.parse_args()
    report = json.dumps(evaluate_archive(args.archive, json.loads(args.holdout_manifest.read_text(encoding='utf-8')) if args.holdout_manifest else None), indent=2) + '\n'
    if args.output:
        args.output.write_text(report, encoding='utf-8')
    else:
        print(report, end='')


if __name__ == '__main__':
    main()
