import csv
import tempfile
import unittest
from pathlib import Path

from services.ddos2019 import analyze_csv
from services.timeline import reconstruct_timelines


class DDoSImportTests(unittest.TestCase):
    def make_csv(self, path, sources):
        with path.open('w', newline='', encoding='utf-8') as output:
            writer = csv.DictWriter(output, fieldnames=['Timestamp', 'Source IP', 'Destination IP', 'Source Port', 'Destination Port', 'Total Fwd Packets', 'Total Backward Packets', 'Label'])
            writer.writeheader()
            for index in range(1200):
                writer.writerow({'Timestamp': '01/12/2018 10:35:00', 'Source IP': sources[index % len(sources)], 'Destination IP': '192.168.50.1', 'Source Port': 40000 + index, 'Destination Port': 80, 'Total Fwd Packets': 10, 'Total Backward Packets': 2, 'Label': 'DDoS'})

    def test_multiple_observed_sources_produce_evidence_linked_case(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'Syn.csv'
            self.make_csv(path, ['10.0.0.1', '10.0.0.2', '10.0.0.3'])
            result = analyze_csv(path)
            self.assertEqual(len(result['alerts']), 1)
            self.assertEqual(result['alerts'][0]['type'], 'DDoS')
            self.assertEqual(result['alerts'][0]['source_count'], 3)
            self.assertEqual({flow['source_ip'] for flow in result['flows']}, {'10.0.0.1', '10.0.0.2', '10.0.0.3'})
            events = reconstruct_timelines(result)['timelines'][0]['events']
            self.assertEqual({event['evidence_id'] for event in events}, {result['alerts'][0]['alert_id'], *(flow['flow_id'] for flow in result['flows'])})

    def test_dataset_label_does_not_override_missing_distribution(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'Syn.csv'
            self.make_csv(path, ['10.0.0.1'])
            self.assertEqual(analyze_csv(path)['alerts'], [])


if __name__ == '__main__':
    unittest.main()
