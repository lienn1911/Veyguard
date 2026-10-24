"""Export one minute of raw traffic around each bundled incident window."""

import argparse
import csv
import io
import json
import zipfile
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

from services.alerts import finite_number, parse_time


def build_context(archive_path, alerts_payload):
    alerts_by_id = {alert['alert_id']: alert for alert in alerts_payload['alerts']}
    cases = {}
    lookup = defaultdict(list)
    for incident in alerts_payload['incidents']:
        pairs = {(alerts_by_id[alert_id]['source_ip'], alerts_by_id[alert_id]['destination_ip'])
                 for alert_id in incident['alert_ids']}
        start = datetime.fromisoformat(incident['window_start'][:16]) - timedelta(minutes=1)
        end = datetime.fromisoformat(incident['window_end'][:16]) + timedelta(minutes=1)
        minutes = {}
        time = start
        while time <= end:
            minutes[time.isoformat(timespec='minutes')] = {'flows': 0, 'packets': 0}
            time += timedelta(minutes=1)
        cases[incident['incident_id']] = {
            'source_file': incident['source_file'],
            'pairs': pairs,
            'start': start,
            'end': end,
            'minutes': minutes,
        }
        for pair in pairs:
            lookup[(incident['source_file'], *pair)].append(incident['incident_id'])

    with zipfile.ZipFile(archive_path) as archive:
        for member in archive.namelist():
            source_file = Path(member).name
            if not member.endswith('.csv') or source_file not in {case['source_file'] for case in cases.values()}:
                continue
            reader = csv.DictReader(io.TextIOWrapper(archive.open(member), encoding='utf-8-sig', newline=''))
            for row in reader:
                values = {key.strip().lower(): str(value).strip() for key, value in row.items() if key}
                incident_ids = lookup.get((source_file, values.get('source ip'), values.get('destination ip')), ())
                if not incident_ids:
                    continue
                minute = parse_time(values['timestamp'], source_file).replace(second=0, microsecond=0)
                for incident_id in incident_ids:
                    case = cases[incident_id]
                    if case['start'] <= minute <= case['end']:
                        bucket = case['minutes'][minute.isoformat(timespec='minutes')]
                        bucket['flows'] += 1
                        bucket['packets'] += int(finite_number(values.get('total fwd packets'))
                                                 + finite_number(values.get('total backward packets')))

    return {
        'scope': 'Raw source/destination flow counts from one minute before through one minute after each incident window.',
        'cases': {
            incident_id: {
                'source_file': case['source_file'],
                'minutes': [{'minute': minute, **counts} for minute, counts in case['minutes'].items()],
            }
            for incident_id, case in cases.items()
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('alerts_json', type=Path)
    parser.add_argument('-o', '--output', required=True, type=Path)
    args = parser.parse_args()
    alerts_payload = json.loads(args.alerts_json.read_text(encoding='utf-8'))
    result = build_context(args.archive, alerts_payload)
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
