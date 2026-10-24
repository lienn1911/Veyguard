# Website and report acceptance 24 October 2026

Status: scoped prototype acceptance passed, including the final isolated Codex replay and review-to-record workflow. This verifies implementation behaviour, not detector accuracy, analyst effectiveness or official competition acceptance.

## Implemented in this revision

- The case tool exposes the complete grouped start and end, and explains that the 60-second rule bucket is not the case duration.
- New results are checked for explicit English window-conflict claims contradicted by actual alert timestamps. Stored successful results are revalidated on read; new runs also carry a case-evidence fingerprint. This is a bounded deterministic check, not general verification of AI semantics.
- The two known contradictory stored proposals are withheld without changing historical runs or audit entries. Assessment confirmation and recommendation approval refuse these proposals. Saved report projections also withhold the affected conclusion.
- The four case tabs explain their current task. Assessment confirmation, investigation-step approval, step completion, record saving and case resolution have distinct meanings and controls.
- Pending review counts exclude absent or invalid AI results. Priority remains an explainable review-order heuristic, with audited analyst overrides; no attack-stage or history-based risk score was added.
- Long alert tables are expandable report appendices. Printing opens appendices. Recommendation choices show selected counts before saving and approved counts afterwards.

## Verified

| Check | Result | Evidence |
| --- | --- | --- |
| Regression | 280 passed, no failures or skips | `data/final-workflow-tests.xml` |
| Frontend production build | Passed; existing large-bundle advisory remains | `node node_modules/vite/bin/vite.js build` |
| Scope and reconstruction | 9 cases, 158 alerts, 948 samples, 1106 traceable events | `evaluation/final-contracts-20261024.json` |
| Synthetic safety contracts | 21 of 21 passed | `evaluation/final-safety-20261024.json` |
| Invalid-result HTTP acceptance | Result hidden, confirmation and approval refused, saved summary excludes invalid conclusion, audit valid, formal state unchanged | `evaluation/final-http-integrity-20261024.json` |
| Native browser UI | Evidence jump, simulated assessment confirmation, step selection and approval, case-note draft and record saving inspected with isolated state | `evaluation/final-native-ui-20261024.json` |
| Final real Codex replay | Needs Review, medium confidence, 4 read-only queries, 4 citations, 2 suggested steps; 54.89 seconds; no validation issues | `evaluation/final-live-workflow-20261024.json` |
| Isolated real-result review | Simulated confirmation, one step approved, DRAFT note and record saved; persisted 10-event shared audit chain verified; formal state unchanged | `data/final-live-acceptance-s7mv0k6_/review/review-audit.db` |
| Word report | 11 pages rendered and inspected; accessibility audit has no findings | `reports/RiskPilot_Technical_Report_Final_20261024.docx` |

The browser acceptance used an explicitly labelled offline mock fixture and `AcceptanceTester`, not a genuine analyst judgment or a live AI performance result. Isolated state is under `data/final-ui-fixture`. It must never be imported as a formal case approval.

## Demo availability after acceptance

The already verified live AI run `TRG-B375AD6F6F` was subsequently registered as the current AI proposal for `INC-A787E11F2A22` using `python -m evaluation.publish_verified_demo_run --apply`. This made the accepted result visible in the normal website without another model call. Its source and evidence fingerprint were checked, and a provenance event was appended to the shared audit chain. The simulated analyst confirmation, step approval, and saved record remain only in the isolated acceptance copy. The normal case still awaits a real analyst decision.

## Competition mapping

Official brief: https://hackai.my/tracks/cyber-defence checked 24 October 2026.

| Required demonstration area | Current support |
| --- | --- |
| Problem and user | SOC analysts reviewing grouped suspected incidents |
| Inputs and evidence | Historical flow data, alert IDs, sample records and source pointers |
| Agent workflow | Model-selected allowlisted read tools, evidence, findings and reported confidence |
| Defensive output | Prioritised review queue and evidence-linked proposed investigation plan |
| Human oversight | Signed-in assessment and step decisions, separate explicit manual resolution |
| Result and limitations | Reproducible software checks, historical detector and AI measurements, disclosed recall and abstention limits |

The brief does not state a detector recall pass mark. Recall tuning was deliberately deferred; existing frozen external results remain unchanged. Historical AI smoke runs are not a substitute for the final prompt and evidence-tool check. The final real-provider run completed after explicit user permission; its output no longer asserts a case-window conflict. The later approval is explicitly simulated in an isolated copy, not a production analyst decision. No slides were produced.

## Reproduction

`python -m evaluation.check_joint_contracts -o evaluation/final-contracts-20261024.json`

`python -m evaluation.evaluate_safety -o evaluation/final-safety-20261024.json`

`python -m evaluation.accept_time_integrity` performs local-only HTTP checks with a test account and separate state. It does not call a model.

`python -m evaluation.accept_final_live_workflow` performs local preflight only. It reports the selected case, destination, input hashes and proposed fields without calling a model or starting an approval. The external-execution flag must only be used after explicit user permission. The prepared final run uses fresh isolated state and verifies the tool and analyst events in one audit chain; it never silently reuses a contradictory cached result.

`python -m evaluation.serve_ui_acceptance --fixture --port=8788` serves the built site with a conspicuous offline-fixture banner and disables model calls and settings changes. It is an internal QA server, not the normal launch command. Normal launch remains `start.cmd`.
