"""Guard the AI evaluation boundary against stale or mock holdout inputs."""

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from evaluation.run_live import (
    DEFAULT_ALERTS,
    DEFAULT_MANIFEST,
    DEFAULT_TIMELINES,
    check_manifest,
    run,
)
from services.config import load_settings


class LiveEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads(DEFAULT_MANIFEST.read_text(encoding="utf-8"))

    def test_current_manifest_matches_bundle(self):
        dataset = check_manifest(self.manifest, DEFAULT_ALERTS, DEFAULT_TIMELINES)
        self.assertTrue(set(self.manifest["case_ids"]).issubset(dataset.incidents))

    def test_changed_bundle_is_rejected(self):
        stale = {**self.manifest, "alerts_sha256": "0" * 64}
        with self.assertRaisesRegex(ValueError, "alerts_sha256"):
            check_manifest(stale, DEFAULT_ALERTS, DEFAULT_TIMELINES)

    def test_holdout_requires_separate_source_and_review(self):
        case_id = self.manifest["case_ids"][0]
        holdout = {
            **self.manifest,
            "kind": "independent-ai-holdout",
            "case_ids": [case_id],
            "reference_labels": {case_id: "Attack"},
        }
        with self.assertRaisesRegex(ValueError, "source archive hash"):
            check_manifest(holdout, DEFAULT_ALERTS, DEFAULT_TIMELINES)
        holdout.update(
            source_archive_sha256="A" * 64,
            development_archive_sha256=["A" * 64],
            reviewed_by="Reviewer",
            frozen_at="2026-10-23T00:00:00Z",
        )
        with self.assertRaisesRegex(ValueError, "distinct"):
            check_manifest(holdout, DEFAULT_ALERTS, DEFAULT_TIMELINES)

    def test_mock_run_is_isolated_and_cannot_score_holdout(self):
        dataset = check_manifest(self.manifest, DEFAULT_ALERTS, DEFAULT_TIMELINES)
        settings = replace(load_settings(), provider="mock")
        smoke = {**self.manifest, "case_ids": self.manifest["case_ids"][:1]}
        scratch = Path(__file__).resolve().parents[1] / "data" / "test-temp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as folder:
            report = run(smoke, dataset, settings, 1, Path(folder) / "report.json")
            self.assertEqual(report["summary"]["runs"], 1)
            self.assertTrue(report["runs"][0]["audit_verified"])
            holdout = {
                **smoke,
                "kind": "independent-ai-holdout",
                "reference_labels": {smoke["case_ids"][0]: "Attack"},
            }
            with self.assertRaisesRegex(ValueError, "mock provider"):
                run(holdout, dataset, settings, 1, Path(folder) / "holdout.json")


if __name__ == "__main__":
    unittest.main()
