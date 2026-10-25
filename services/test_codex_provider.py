"""Codex CLI adapter contracts without spending account allowance."""

import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from services.providers.base import ProviderRateLimited
from services.providers.codex_provider import CodexProvider


class CodexProviderTests(unittest.TestCase):
    def test_codex_tool_turn_runs_isolated_and_parses_tool_call(self):
        def fake_run(command, **kwargs):
            self.assertEqual(command[command.index("--sandbox") + 1], "read-only")
            self.assertIn("--ephemeral", command)
            self.assertIn("--ignore-user-config", command)
            self.assertIn("--skip-git-repo-check", command)
            self.assertNotIn("-m", command)
            self.assertIn("get_incident_details", kwargs["input"])
            output = Path(command[command.index("--output-last-message") + 1])
            output.write_text(
                json.dumps(
                    {
                        "kind": "tool",
                        "tool": "get_incident_details",
                        "arguments": '{"incident_id":"INC-ABCDEF"}',
                        "answer": "",
                    }
                ),
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(command, 0, "", "")

        provider = CodexProvider(executable="codex", model="default")
        with patch("services.providers.codex_provider.subprocess.run", side_effect=fake_run):
            turn = provider.complete(
                [{"role": "user", "content": "Investigate"}],
                [{"name": "get_incident_details", "description": "Read", "parameters": {}}],
            )
        self.assertEqual(turn.tool_calls[0].arguments, {"incident_id": "INC-ABCDEF"})

    def test_codex_usage_limit_is_not_silently_retried(self):
        provider = CodexProvider(executable="codex")
        result = subprocess.CompletedProcess([], 1, "", "Error: usage limit reached")
        with patch("services.providers.codex_provider.subprocess.run", return_value=result):
            with self.assertRaises(ProviderRateLimited):
                provider.complete([], [])
