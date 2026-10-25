"""Run the isolated UI preview with a dedicated local state directory."""

import os
import runpy

if __name__ == "__main__":
    os.environ["SOC_TRIAGE_UI_WORKDIR"] = "compact-ui-check-20261024"
    runpy.run_module("evaluation.serve_ui_acceptance", run_name="__main__")
