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
    if len(group['ports']) >= 100 and len(group['source_ports']) >= 10 and group['count'] >= 100:
        return 'PortScan'
    if group['count'] >= 1000 and group['packets'] >= 10000:
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


def analyze_archive(path, limit_per_type=2):
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

    selected = []
    for kind in ('PortScan', 'DoS', 'DDoS'):
        candidates = [item for item in matches if item['type'] == kind]
        candidates.sort(key=lambda item: (item['group']['count'], len(item['group']['ports'])), reverse=True)
        seen_files = set()
        for candidate in candidates:
            source_file = candidate['key'][0]
            if source_file in seen_files:
                continue
            selected.append(candidate)
            seen_files.add(source_file)
            if len(seen_files) >= limit_per_type:
                break
    reference_candidates = [item for item in matches if item['group']['labels'].get('DDoS', 0) > 0]
    reference_candidates.sort(key=lambda item: item['group']['count'], reverse=True)
    selected_keys = {item['key'] for item in selected}
    ddos_reference_count = sum(item['group']['labels'].get('DDoS', 0) > 0 for item in selected)
    for candidate in reference_candidates:
        if ddos_reference_count >= 3:
            break
        if candidate['key'] not in selected_keys:
            selected.append(candidate)
            selected_keys.add(candidate['key'])
            ddos_reference_count += 1
    selected.sort(key=lambda item: (item['key'][3], item['key'][0], item['key'][1]))

    flows = []
    alerts = []
    incidents = []
    for item in selected:
        source_file, source, destination, minute = item['key']
        group = item['group']
        evidence = group['samples'][:]
        if group['last']['flow_id'] not in {flow['flow_id'] for flow in evidence}:
            evidence.append(group['last'])
        evidence.sort(key=lambda flow: (flow['timestamp'], flow['source_row']))
        flow_ids = [flow['flow_id'] for flow in evidence]
        incident_id = stable_id('INC', source_file, source, destination, minute)
        alert_id = stable_id('ALT', incident_id, item['type'])
        flows.extend(evidence)
        alerts.append({
            'alert_id': alert_id,
            'incident_id': incident_id,
            'type': item['type'],
            'timestamp': evidence[-1]['timestamp'],
            'source_ip': source,
            'destination_ip': destination,
            'flow_count': group['count'],
            'destination_port_count': len(group['ports']),
            'source_port_count': len(group['source_ports']),
            'source_count': item.get('source_count', 1),
            'evidence_sample_ids': flow_ids,
            'dataset_labels': dict(sorted(group['labels'].items())),
            'ddos_reference': group['labels'].get('DDoS', 0) > 0,
            'rule_basis': f"{len(group['ports'])} destination ports, {len(group['source_ports'])} source ports in one minute" if item['type'] == 'PortScan' else f"{group['count']} flows, {int(group['packets'])} packets, {item['source_count']} independent source IPs in one minute" if item['type'] == 'DDoS' else f"{group['count']} flows and {int(group['packets'])} packets in one minute",
        })
        incidents.append({
            'incident_id': incident_id,
            'source_ip': source,
            'destination_ip': destination,
            'window_start': f'{minute}:00',
            'alert_ids': [alert_id],
            'evidence_sample_ids': flow_ids,
            'flow_count': group['count'],
            'source_file': source_file,
        })
    return {
        'provenance': {'dataset': 'CIC-IDS2017 GeneratedLabelledFlows', 'archive': Path(path).name, 'files': members_read, 'scope': 'Selected full one-minute groups; sampled evidence records shown'},
        'rules': {'window_seconds': 60, 'portscan_min_destination_ports': 100, 'portscan_min_source_ports': 10, 'portscan_min_flows': 100, 'dos_min_flows': 1000, 'dos_min_packets': 10000, 'ddos_min_sources': 3},
        'evaluation': {'groups_scanned': len(groups), 'rule_matches': len(matches), 'preview_cases': len(selected)},
        'flows': flows,
        'alerts': alerts,
        'incidents': incidents,
    }


def main():
    parser = argparse.ArgumentParser(description='Generate rule-based alert preview from CIC-IDS2017 labeled flows')
    parser.add_argument('archive', type=Path)
    parser.add_argument('-o', '--output', type=Path, required=True)
    parser.add_argument('--limit-per-type', type=int, default=2)
    args = parser.parse_args()
    result = analyze_archive(args.archive, args.limit_per_type)
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
