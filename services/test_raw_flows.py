import csv
import io
import tempfile
import unittest
import zipfile
from pathlib import Path

from services.raw_flows import ROOT, database_status, import_archive, query_case_flows


class RawFlowImportTest(unittest.TestCase):
    def test_complete_fields_and_case_scoped_paging(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'data') as directory:
            root = Path(directory)
            archive = root / 'flows.zip'
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=['Flow ID', 'Source IP', 'Source Port',
                                                       'Destination IP', 'Destination Port', 'Protocol',
                                                       'Timestamp', 'Total Fwd Packets', 'Total Backward Packets',
                                                       'Flow Duration'])
            writer.writeheader()
            for index, minute in enumerate(('09:29:00', '09:30:11', '09:30:12', '09:31:00'), 1):
                writer.writerow({'Flow ID': f'flow-{index}', 'Source IP': '10.0.0.1', 'Source Port': str(1000 + index),
                                 'Destination IP': '10.0.0.2', 'Destination Port': '443', 'Protocol': '6',
                                 'Timestamp': f'03/07/2017 {minute}', 'Total Fwd Packets': '2',
                                 'Total Backward Packets': '3', 'Flow Duration': '42'})
            writer.writerow({'Flow ID': 'undated', 'Source IP': '10.0.0.1', 'Source Port': '2000',
                             'Destination IP': '10.0.0.2', 'Destination Port': '443', 'Protocol': '6',
                             'Timestamp': '', 'Total Fwd Packets': '1', 'Total Backward Packets': '1'})
            writer.writerow({})
            with zipfile.ZipFile(archive, 'w') as zipped:
                zipped.writestr('TrafficLabelling /Monday-WorkingHours.pcap_ISCX.csv', output.getvalue())
            db = root / 'raw.db'
            import_archive(archive, db)
            self.assertEqual(database_status(db)['rows'], 5)
            self.assertEqual(database_status(db)['files'][0]['invalid_timestamps'], 1)
            self.assertEqual(database_status(db)['files'][0]['blank_rows_skipped'], 1)
            incident = {'source_file': 'Monday-WorkingHours.pcap_ISCX.csv',
                        'window_start': '2017-07-03T09:30:59', 'window_end': '2017-07-03T09:30:59'}
            alerts = [{'source_ip': '10.0.0.1', 'destination_ip': '10.0.0.2'}]
            result = query_case_flows(incident, alerts, minute='2017-07-03T09:30', page_size=1, db_path=db)
            self.assertEqual(result['total'], 2)
            self.assertEqual(result['records'][0]['fields']['Flow Duration'], '42')
            self.assertEqual(query_case_flows(incident, alerts, minute='2017-07-03T09:31', db_path=db)['total'], 1)
            with self.assertRaises(ValueError):
                query_case_flows(incident, alerts, minute='2017-07-03T09:32', db_path=db)


if __name__ == '__main__':
    unittest.main()
