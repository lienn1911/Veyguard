import argparse
import csv
import hashlib
import io
import json
import math
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path


DEFAULT_MEMBERS = ('Wednesday-workingHours', 'Friday-WorkingHours-Afternoon-DDos', 'Friday-WorkingHours-Afternoon-PortScan')
INCIDENT_GAP_MINUTES = 5


def stable_id(prefix, *parts):
    value = '\x1f'.join(str(part) for part in parts)
    return f'{prefix}-{hashlib.sha256(value.encode()).hexdigest()[:12].upper()}'


def parse_time(value, source_file):
    for format_string in ('%d/%m/%Y %H:%M:%S', '%d/%m/%Y %H:%M', '%Y-%m-%d %H:%M:%S'):
        try:
            time = datetime.strptime(value, format_string)
            if 'Afternoon' in source_file and 1 <= time.hour < 12:
                time += timedelta(hours=12)
            return time
        except ValueError:
            continue
    raise ValueError(f'Unsupported timestamp {value!r} in {source_file}')


def finite_number(value):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0
    return number if math.isfinite(number) and number >= 0 else 0


def read_flow(row, source_file, row_number):
    values = {key.strip().lower(): str(value).strip() for key, value in row.items() if key}
    source = values.get('source ip', '')
    destination = values.get('destination ip', '')
    port = values.get('destination port', '')
    source_port = values.get('source port', '')
    if not (source and destination and port and values.get('timestamp')):
        raise ValueError(f'Missing flow identifiers in {source_file}:{row_number}')
    time = parse_time(values['timestamp'], source_file)
    return {
        'flow_id': stable_id('FLOW', source_file, row_number, values.get('flow id', '')),
        'timestamp': time.isoformat(),
        'source_ip': source,
        'destination_ip': destination,
        'destination_port': port,
        'source_port': source_port,
        'packet_count': finite_number(values.get('total fwd packets')) + finite_number(values.get('total backward packets')),
        'dataset_label': values.get('label', ''),
        'source_file': source_file,
        'source_row': row_number,
        'original_flow_id': values.get('flow id', ''),
    }


def classify_group(group):
    if len(group['ports']) >= 100 and len(group['source_ports']) >= 2 * len(group['ports']) and group['count'] >= 100:
        return 'PortScan'
    if group['count'] >= 1000 and group['packets'] >= 10000 and len(group['ports']) <= 10 and len(group['source_ports']) >= 10:
        return 'DoS'
    return None


def mark_distributed_floods(matches):
    grouped_sources = defaultdict(list)
    for match in matches:
        if match['type'] == 'DoS':
            source_file, source, destination, minute = match['key']
            grouped_sources[(source_file, destination, minute)].append(match)
    for items in grouped_sources.values():
        source_count = len({item['key'][1] for item in items})
        if source_count >= 3:
            for item in items:
                item['type'] = 'DDoS'
                item['source_count'] = source_count


def group_alerts(alerts):
    incidents = []
    current = None
    last_time = None
    for alert in sorted(alerts, key=lambda item: (item['source_file'], item['source_ip'], item['destination_ip'], item['timestamp'], item['alert_id'])):
        key = (alert['source_file'], alert['source_ip'], alert['destination_ip'])
        time = datetime.fromisoformat(alert['timestamp'])
        if current is None or current['_key'] != key or time - last_time > timedelta(minutes=INCIDENT_GAP_MINUTES):
            current = {
                'incident_id': stable_id('INC', *key, alert['timestamp']),
                'source_ip': alert['source_ip'],
                'destination_ip': alert['destination_ip'],
                'window_start': alert['timestamp'],
                'window_end': alert['timestamp'],
                'alert_ids': [],
                'evidence_sample_ids': [],
                'flow_count': 0,
                'source_file': alert['source_file'],
                '_key': key,
            }
            incidents.append(current)
        alert['incident_id'] = current['incident_id']
        current['alert_ids'].append(alert['alert_id'])
        current['evidence_sample_ids'].extend(alert['evidence_sample_ids'])
        current['flow_count'] += alert['flow_count']
        current['window_end'] = alert['timestamp']
        last_time = time
    for incident in incidents:
        del incident['_key']
    incidents.sort(key=lambda item: (item['window_start'], item['incident_id']))
    return incidents


def select_preview(incidents, alerts, flows, limit):
    alerts_by_id = {alert['alert_id']: alert for alert in alerts}
    chosen = []
    seen = set()

    def add(incident):
        if incident and incident['incident_id'] not in seen and len(chosen) < limit:
            chosen.append(incident)
            seen.add(incident['incident_id'])

    ranked = sorted(incidents, key=lambda item: (-item['flow_count'], item['window_start'], item['incident_id']))
    for predicate in (
        lambda alert: alert['type'] == 'PortScan',
        lambda alert: alert['type'] == 'DoS' and not alert['ddos_reference'],
        lambda alert: alert['ddos_reference'],
    ):
        add(next((incident for incident in ranked if any(predicate(alerts_by_id[alert_id]) for alert_id in incident['alert_ids'])), None))
    for incident in ranked:
        add(incident)
    chosen.sort(key=lambda item: (item['window_start'], item['incident_id']))
    chosen_alert_ids = {alert_id for incident in chosen for alert_id in incident['alert_ids']}
    chosen_flow_ids = {flow_id for incident in chosen for flow_id in incident['evidence_sample_ids']}
    return chosen, [alert for alert in alerts if alert['alert_id'] in chosen_alert_ids], [flow for flow in flows if flow['flow_id'] in chosen_flow_ids]


def make_preview(result, limit):
    incidents, alerts, flows = select_preview(result['incidents'], result['alerts'], result['flows'], limit)
    return {
        **result,
        'provenance': {**result['provenance'], 'mode': 'preview'},
        'evaluation': {**result['evaluation'], 'exported_incidents': len(incidents), 'exported_alerts': len(alerts)},
        'incidents': incidents,
        'alerts': alerts,
        'flows': flows,
    }


def analyze_archive(path, preview_cases=None):
    groups = {}
    members_read = []
    with zipfile.ZipFile(path) as archive:
        members = [name for name in archive.namelist() if name.endswith('.csv') and any(part in name for part in DEFAULT_MEMBERS)]
        if len(members) != len(DEFAULT_MEMBERS):
            raise ValueError('Expected Wednesday DoS, Friday DDoS, and Friday PortScan labeled-flow CSVs')
        for member in members:
            source_file = Path(member).name
            members_read.append(source_file)
            reader = csv.DictReader(io.TextIOWrapper(archive.open(member), encoding='utf-8-sig', newline=''))
            for row_number, row in enumerate(reader, start=2):
                flow = read_flow(row, source_file, row_number)
                minute = flow['timestamp'][:16]
                key = (source_file, flow['source_ip'], flow['destination_ip'], minute)
                if key not in groups:
                    groups[key] = {'count': 0, 'packets': 0, 'ports': set(), 'source_ports': set(), 'labels': Counter(), 'samples': [], 'last': None}
                group = groups[key]
                group['count'] += 1
                group['packets'] += flow['packet_count']
                group['ports'].add(flow['destination_port'])
                group['source_ports'].add(flow['source_port'])
                group['labels'][flow['dataset_label']] += 1
                if len(group['samples']) < 5:
                    group['samples'].append(flow)
                group['last'] = flow

    matches = []
    for key, group in groups.items():
        kind = classify_group(group)
        if not kind:
            continue
        match = {'key': key, 'group': group, 'type': kind}
        matches.append(match)
    mark_distributed_floods(matches)

    flows = []
    alerts = []
    for item in sorted(matches, key=lambda match: match['key']):
        source_file, source, destination, minute = item['key']
        group = item['group']
        evidence = group['samples'][:]
        if group['last']['flow_id'] not in {flow['flow_id'] for flow in evidence}:
            evidence.append(group['last'])
        evidence.sort(key=lambda flow: (flow['timestamp'], flow['source_row']))
        flow_ids = [flow['flow_id'] for flow in evidence]
        alert_id = stable_id('ALT', source_file, source, destination, minute, item['type'])
        flows.extend(evidence)
        alerts.append({
            'alert_id': alert_id,
            'type': item['type'],
            'timestamp': evidence[-1]['timestamp'],
            'source_file': source_file,
            'source_ip': source,
            'destination_ip': destination,
            'flow_count': group['count'],
            'destination_port_count': len(group['ports']),
            'source_port_count': len(group['source_ports']),
            'source_count': item.get('source_count', 1),
            'evidence_sample_ids': flow_ids,
            'dataset_labels': dict(sorted(group['labels'].items())),
            'ddos_reference': group['labels'].get('DDoS', 0) > 0,
            'rule_basis': f"{len(group['ports'])} destination ports, {len(group['source_ports'])} source ports in one minute" if item['type'] == 'PortScan' else f"{group['count']} flows, {int(group['packets'])} packets, {item.get('source_count', 1)} independent source IPs in one minute" if item['type'] == 'DDoS' else f"{group['count']} flows and {int(group['packets'])} packets in one minute",
        })
    incidents = group_alerts(alerts)
    result = {
        'provenance': {'dataset': 'CIC-IDS2017 GeneratedLabelledFlows', 'archive': Path(path).name, 'files': members_read, 'mode': 'full', 'scope': 'All matching one-minute alerts; up to six sampled source flows per alert'},
        'rules': {'window_seconds': 60, 'incident_gap_minutes': INCIDENT_GAP_MINUTES, 'portscan_min_destination_ports': 100, 'portscan_min_source_port_ratio': 2, 'portscan_min_flows': 100, 'dos_min_flows': 1000, 'dos_min_packets': 10000, 'dos_max_destination_ports': 10, 'dos_min_source_ports': 10, 'ddos_min_sources': 3},
        'evaluation': {'groups_scanned': len(groups), 'rule_matches': len(matches), 'incidents': len(incidents), 'exported_incidents': len(incidents), 'exported_alerts': len(alerts)},
        'flows': flows,
        'alerts': alerts,
        'incidents': incidents,
    }
    return make_preview(result, preview_cases) if preview_cases is not None else result


def main():
    parser = argparse.ArgumentParser(description='Generate rule-based alerts and incidents from CIC-IDS2017 labeled flows')
    parser.add_argument('archive', type=Path, nargs='?')
    parser.add_argument('-o', '--output', type=Path, required=True)
    parser.add_argument('--preview-cases', type=int)
    parser.add_argument('--preview-from', type=Path)
    args = parser.parse_args()
    if args.preview_cases is not None and args.preview_cases < 1:
        parser.error('--preview-cases must be positive')
    if args.preview_from:
        if args.archive or args.preview_cases is None:
            parser.error('--preview-from requires --preview-cases and no archive')
        result = make_preview(json.loads(args.preview_from.read_text(encoding='utf-8')), args.preview_cases)
    else:
        if not args.archive:
            parser.error('archive is required without --preview-from')
        result = analyze_archive(args.archive, args.preview_cases)
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
