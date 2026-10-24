import json
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from services.auto_analysis import AutoAnalysis


class AutoAnalysisTests(unittest.TestCase):
    def test_opt_in_is_persisted_and_a_failed_case_is_not_retried(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1] / 'data') as folder:
            root = Path(folder)
            cases = root / 'cases.json'
            setting = root / 'auto.json'
            cases.write_text(json.dumps({'incidents': [{'incident_id': 'one'}]}), encoding='utf-8')
            calls = []
            service = SimpleNamespace(settings=SimpleNamespace(is_mock=False), investigate=lambda case_id: calls.append(case_id) or {'status': 'error', 'error': {'code': 'PROVIDER_RATE_LIMITED'}})
            coordinator = AutoAnalysis(cases, setting, lambda _: {'status': 'pending'}, lambda: service)
            self.assertFalse(coordinator.status()['enabled'])
            coordinator.set_enabled(True)
            self.assertTrue(json.loads(setting.read_text(encoding='utf-8'))['enabled'])
            # The worker may start immediately or on its next wake-up.
            for _ in range(100):
                if coordinator.status()['paused_reason']:
                    break
                coordinator.wake.set()
                time.sleep(0.01)
            self.assertEqual(calls, ['one'])
            self.assertIn('quota', coordinator.status()['paused_reason'])
            coordinator.set_enabled(False)


if __name__ == '__main__':
    unittest.main()
