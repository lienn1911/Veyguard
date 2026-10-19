import argparse
import json
from pathlib import Path


TECHNIQUES = {
    'PortScan': {'id': 'T1046', 'name': 'Network Service Discovery'},
    'DoS': 'Unmapped',
    'DDoS': {'id': 'T1498', 'name': 'Network Denial of Service'},
}


def reconstruct_timelines(result):
    flows = {flow['flow_id']: flow for flow in result['flows']}
    alerts = {alert['alert_id']: alert for alert in result['alerts']}
    timelines = []
    for incident in result['incidents']:
        events = []
        for flow_id in incident['evidence_sample_ids']:
            flow = flows[flow_id]
            events.append({
                'timestamp': flow['timestamp'],
                'title': f"{flow['source_ip']} → port {flow['destination_port']}",
                'record_type': 'flow',
                'evidence_id': flow_id,
                'source_file': flow['source_file'],
                'source_row': flow['source_row'],
                'technique': 'Unmapped',
            })
        for alert_id in incident['alert_ids']:
            alert = alerts[alert_id]
            events.append({
                'timestamp': alert['timestamp'],
                'title': f"{alert['type']} rule matched",
                'record_type': 'alert',
                'evidence_id': alert_id,
                'technique': TECHNIQUES.get(alert['type'], 'Unmapped'),
            })
        events.sort(key=lambda event: (event['timestamp'], event['record_type'] != 'flow', event['evidence_id']))
        timelines.append({'incident_id': incident['incident_id'], 'total_flows': incident['flow_count'], 'sampled_events': len(events), 'events': events})
    return {'timelines': timelines}


def main():
    parser = argparse.ArgumentParser(description='Reconstruct evidence-linked timelines from rule-based alerts')
    parser.add_argument('alerts_json', type=Path)
    parser.add_argument('-o', '--output', type=Path, required=True)
    args = parser.parse_args()
    result = json.loads(args.alerts_json.read_text(encoding='utf-8'))
    args.output.write_text(json.dumps(reconstruct_timelines(result), indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
