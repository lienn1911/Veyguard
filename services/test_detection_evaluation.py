import csv
import io
import tempfile
import unittest
import zipfile
from pathlib import Path

from services.alerts import classify_group, needs_review_candidate
from services.evaluate_detection import evaluate_archive


class DetectionEvaluationTests(unittest.TestCase):
    def test_dense_port_scan_with_reused_source_ports_matches(self):
        group = {'count': 100, 'packets': 200, 'ports': set(range(250)), 'source_ports': {40000, 40001}}
        self.assertEqual(classify_group(group), 'PortScan')

    def test_response_like_port_sweep_stays_unclassified(self):
        group = {'count': 225, 'packets': 450, 'ports': set(range(225)), 'source_ports': set(range(164))}
        self.assertIsNone(classify_group(group))

    def test_unclassified_candidate_is_not_a_known_attack(self):
        group = {'count': 500, 'packets': 5000, 'ports': {'80'}, 'source_ports': {'1000'}}
        self.assertIsNone(classify_group(group))
        self.assertTrue(needs_review_candidate(group))

    def test_full_archive_reports_missed_attack_and_benign_group(self):
        header = ['Source IP', 'Destination IP', 'Destination Port', 'Source Port', 'Timestamp',
                  'Total Fwd Packets', 'Total Backward Packets', 'Label']
        with tempfile.TemporaryDirectory() as folder:
            archive_path = Path(folder) / 'flows.zip'
            with zipfile.ZipFile(archive_path, 'w') as archive:
                for member, label in [('Monday-WorkingHours.csv', 'BENIGN'),
                                      ('Tuesday-WorkingHours.csv', 'BENIGN'),
                                      ('Wednesday-workingHours.csv', 'DoS Hulk'),
                                      ('Friday-WorkingHours-Afternoon-PortScan.csv', 'BENIGN')]:
                    buffer = io.StringIO()
                    writer = csv.writer(buffer)
                    writer.writerow(header)
                    writer.writerow(['10.0.0.1', '10.0.0.2', 80, 1000, '05/07/2017 10:00:00', 1, 1, label])
                    archive.writestr(member, buffer.getvalue())
            report = evaluate_archive(archive_path)
        self.assertEqual(report['per_type']['DoS']['false_negative'], 1)
        self.assertEqual(report['per_type']['DoS']['recall'], 0)
        self.assertEqual(report['attack_detection']['true_positive'], 0)
        self.assertEqual(report['attack_detection']['false_negative'], 1)
        self.assertEqual(report['attack_detection']['false_positive'], 0)
        self.assertEqual(report['groups_scanned'], 4)

    def test_repeated_ssh_flows_are_detected_without_login_outcome(self):
        header = ['Source IP', 'Destination IP', 'Destination Port', 'Source Port', 'Timestamp',
                  'Total Fwd Packets', 'Total Backward Packets', 'Label']
        with tempfile.TemporaryDirectory() as folder:
            archive_path = Path(folder) / 'flows.zip'
            with zipfile.ZipFile(archive_path, 'w') as archive:
                for member in ('Monday-WorkingHours.csv', 'Tuesday-WorkingHours.csv', 'Wednesday-workingHours.csv',
                               'Friday-WorkingHours-Afternoon-PortScan.csv'):
                    buffer = io.StringIO()
                    writer = csv.writer(buffer)
                    writer.writerow(header)
                    if 'Tuesday' in member:
                        for index in range(50):
                            writer.writerow(['10.0.0.1', '10.0.0.2', 22, 1000 + index,
                                             '04/07/2017 09:00:00', 1, 0, 'SSH-Patator'])
                    archive.writestr(member, buffer.getvalue())
            report = evaluate_archive(archive_path)
        self.assertEqual(report['attack_detection']['true_positive'], 1)
        self.assertEqual(report['per_type']['BruteForce']['true_positive'], 1)
        self.assertEqual(report['per_type']['BruteForce']['missed_without_alert'], 0)


if __name__ == '__main__':
    unittest.main()
