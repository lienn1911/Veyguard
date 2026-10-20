import argparse
import csv
import io
import json
import tarfile
from collections import Counter, defaultdict
from pathlib import Path

from services.alerts import stable_id
from services.timeline import reconstruct_timelines


SOURCE_FILE = 'normal_synflood_ddos/nsg.csv'
LABEL_FILE = 'normal_synflood_ddos/label.csv'
MIN_SOURCES = 3
MIN_FLOWS_PER_SOURCE = 1000
MIN_TOTAL_PACKETS = 10000


def read_labels(archive, minute):
    labels = {}
    with io.TextIOWrapper(archive.extractfile(LABEL_FILE), encoding='utf-8-sig', newline='') as stream:
        for source, destination, window, label in csv.reader(stream):
            if window.replace(' ', 'T')[:16] == minute:
                labels[(source, destination)] = label
    return labels


def analyze_archive(path, minute='2023-03-15T11:56', destination='172.0.0.19'):
    sources = defaultdict(lambda: {'flows': 0, 'packets': 0, 'first': None, 'last': None, 'destination_ports': set(), 'source_ports': set()})
    with tarfile.open(path, 'r:gz') as archive:
        labels = read_labels(archive, minute)
        with io.TextIOWrapper(archive.extractfile(SOURCE_FILE), encoding='utf-8-sig', newline='') as stream:
            for row_number, row in enumerate(csv.reader(stream), start=1):
                if len(row) < 13 or row[0][:16] != minute or row[2] != destination or row[5] != 'T':
                    continue
                source = row[1]
                packets = sum(int(row[index]) for index in (9, 11) if row[index].isdigit())
                flow = {
                    'flow_id': stable_id('FLOW', SOURCE_FILE, row_number),
                    'timestamp': row[0].replace('Z', '+00:00'),
                    'source_ip': source,
                    'destination_ip': destination,
                    'source_port': row[3],
                    'destination_port': row[4],
                    'packet_count': packets,
                    'dataset_label': labels.get((source, destination), ''),
                    'source_file': SOURCE_FILE,
                    'source_row': row_number,
                }
                item = sources[source]
                item['flows'] += 1
                item['packets'] += packets
                item['destination_ports'].add(row[4])
                item['source_ports'].add(row[3])
                item['first'] = item['first'] or flow
                item['last'] = flow

    contributors = {source: item for source, item in sources.items() if item['flows'] >= MIN_FLOWS_PER_SOURCE}
    total_flows = sum(item['flows'] for item in contributors.values())
    total_packets = sum(item['packets'] for item in contributors.values())
    if len(contributors) < MIN_SOURCES or total_packets < MIN_TOTAL_PACKETS:
        raise ValueError('The selected minute does not have enough independently contributing sources')

    evidence = sorted((flow for item in contributors.values() for flow in (item['first'], item['last'])), key=lambda flow: (flow['timestamp'], flow['source_row']))
    alert_id = stable_id('ALT', SOURCE_FILE, destination, minute, 'DDoS')
    incident_id = stable_id('INC', SOURCE_FILE, destination, minute)
    alert = {
        'alert_id': alert_id,
        'incident_id': incident_id,
        'type': 'DDoS',
        'timestamp': evidence[-1]['timestamp'],
        'source_file': SOURCE_FILE,
        'source_ip': 'Multiple sources',
        'destination_ip': destination,
        'flow_count': total_flows,
        'destination_port_count': len(set().union(*(item['destination_ports'] for item in contributors.values()))),
        'source_port_count': len(set().union(*(item['source_ports'] for item in contributors.values()))),
        'source_count': len(contributors),
        'source_contributions': dict(sorted((source, item['flows']) for source, item in contributors.items())),
        'evidence_sample_ids': [flow['flow_id'] for flow in evidence],
        'dataset_labels': dict(Counter(flow['dataset_label'] for flow in evidence)),
        'ddos_reference': all(flow['dataset_label'] == '1' for flow in evidence),
        'rule_basis': f'{total_flows:,} TCP records and {total_packets:,} packets from {len(contributors)} sources in one minute; each source contributed at least {MIN_FLOWS_PER_SOURCE:,} records',
    }
    incident = {
        'incident_id': incident_id,
        'source_ip': 'Multiple sources',
        'destination_ip': destination,
        'window_start': evidence[0]['timestamp'],
        'window_end': evidence[-1]['timestamp'],
        'alert_ids': [alert_id],
        'evidence_sample_ids': alert['evidence_sample_ids'],
        'flow_count': total_flows,
        'source_file': SOURCE_FILE,
    }
    return {'flows': evidence, 'alerts': [alert], 'incidents': [incident]}


def main():
    parser = argparse.ArgumentParser(description='Add an evidence-linked Yatesbury SYN DDoS case')
    parser.add_argument('archive', type=Path)
    parser.add_argument('--alerts-output', type=Path, required=True)
    parser.add_argument('--timelines-output', type=Path, required=True)
    args = parser.parse_args()
    result = analyze_archive(args.archive)
    data = json.loads(args.alerts_output.read_text(encoding='utf-8'))
    for key in ('flows', 'alerts', 'incidents'):
        data[key] = [item for item in data[key] if item.get('source_file') != SOURCE_FILE] + result[key]
    data['provenance']['additional_dataset'] = 'Microsoft Yatesbury SYN Flood DDoS scenario'
    data['evaluation']['exported_incidents'] = len(data['incidents'])
    data['evaluation']['exported_alerts'] = len(data['alerts'])
    args.alerts_output.write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')
    args.timelines_output.write_text(json.dumps(reconstruct_timelines(data), indent=2) + '\n', encoding='utf-8')
    print(f"Added one DDoS case with {result['alerts'][0]['source_count']} sources and {result['alerts'][0]['flow_count']:,} records")


if __name__ == '__main__':
    main()
