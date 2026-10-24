"""Prepare, or explicitly run, final isolated Codex workflow acceptance.

Default invocation performs LOCAL PREFLIGHT ONLY. The external-run flag is an
execution guard, not consent: obtain the user's data-transfer permission first.
No run is silently retried and no production approval or case state is changed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from dataclasses import replace
from pathlib import Path

from services.config import load_settings
from services.data_store import Dataset

ROOT = Path(__file__).resolve().parents[1]
CASE = 'INC-A787E11F2A22'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None


def run(*, allow_external=False):
    settings = load_settings()
    dataset = Dataset.load(settings.alerts_path, settings.timelines_path)
    incident = dataset.require(CASE).incident
    report = {
        'kind': 'final-isolated-live-workflow-acceptance',
        'incident_id': CASE,
        'provider': settings.provider,
        'model': settings.model,
        'case_window': [incident['window_start'], incident['window_end']],
        'inputs': {str(path.relative_to(ROOT)): digest(path) for path in
                   (settings.alerts_path, settings.timelines_path, ROOT/'services/prompts.py')},
        'transmitted_fields_if_authorised': ['case addresses and time bounds',
            'traffic aggregates', 'linked alert measurements and IDs',
            'sample flow addresses, ports, times, packet counts and IDs'],
        'external_model_calls_started': False,
        'passed': False,
        'status': 'awaiting_explicit_data_transfer_permission',
    }
    if not allow_external:
        return report
    if settings.provider != 'codex':
        raise ValueError('This acceptance request covers the configured Codex service only.')

    # Import the workflow only after the no-network preflight gate.
    from services.triage import TriageService
    from evaluation.accept_current_case_flow import run as exercise_review
    production = (settings.state_path, ROOT/'data/audit.db', ROOT/'data/auth/account.json')
    before = {str(path): digest(path) for path in production}
    work = Path(tempfile.mkdtemp(prefix='final-live-acceptance-', dir=ROOT/'data'))
    isolated = replace(settings, state_path=work/'state.json', audit_path=work/'audit.db')
    triage = TriageService(isolated, dataset)
    report['external_model_calls_started'] = True
    result = triage.investigate(CASE)
    report.update(status=result['status'], run_id=result['run_id'], error=result.get('error'))
    (work/'live-result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    if result['status'] == 'ok':
        try:
            workflow = exercise_review(CASE, source_state=isolated.state_path, source_audit=isolated.audit_path, artifacts_dir=work/'review')
            report['workflow'] = workflow
            report['passed'] = workflow['audit_chain_valid'] and not workflow['production_state_changed']
        except (AssertionError, ValueError, LookupError) as error:
            report.update(status='workflow_failed', error={'message': str(error) or 'A workflow invariant failed.'})
    after = {str(path): digest(path) for path in production}
    report['production_unchanged'] = before == after
    report['passed'] = report['passed'] and report['production_unchanged']
    report['analyst_role'] = 'Simulated approval in an isolated copy; not an actual analyst judgment.'
    report['run_artifacts'] = str(work.relative_to(ROOT))
    output = ROOT/'evaluation/final-live-workflow-20261024.json'
    output.write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--allow-external-demonstration-evidence', action='store_true',
                        help='Execute only after explicit user permission for this case and Codex destination.')
    args = parser.parse_args()
    report = run(allow_external=args.allow_external_demonstration_evidence)
    print(json.dumps(report, indent=2))
    return 0 if not args.allow_external_demonstration_evidence or report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
