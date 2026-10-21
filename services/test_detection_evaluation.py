import csv
import io
import tempfile
import unittest
import zipfile
from pathlib import Path

from services.alerts import classify_group, needs_review_candidate
from services.evaluate_detection import evaluate_archive


class DetectionEvaluationTests(unittest.TestCase):
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
                for member, label in [('Wednesday-workingHours.csv', 'DoS Hulk'),
                                      ('Friday-WorkingHours-Afternoon-DDos.csv', 'BENIGN'),
                                      ('Friday-WorkingHours-Afternoon-PortScan.csv', 'BENIGN')]:
                    buffer = io.StringIO()
                    writer = csv.writer(buffer)
                    writer.writerow(header)
                    writer.writerow(['10.0.0.1', '10.0.0.2', 80, 1000, '05/07/2017 10:00:00', 1, 1, label])
                    archive.writestr(member, buffer.getvalue())
            report = evaluate_archive(archive_path)
        self.assertEqual(report['per_type']['DoS']['false_negative'], 1)
        self.assertEqual(report['per_type']['DoS']['recall'], 0)
        self.assertEqual(report['groups_scanned'], 3)


if __name__ == '__main__':
    unittest.main()
