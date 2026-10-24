# SOC Desk evaluation protocol â€” draft frozen before live model runs

Date: 2026-10-22 (Asia/Kuala_Lumpur). This document records the intended measurement and its limits. Changing the protocol after viewing test results requires a dated revision; report both versions.

## Claims and units

Report three layers separately: (1) rule detection on all eligible source/destination/minute groups, including missed attacks; (2) AI triage *conditional on an input case existing*; (3) workflow safety after analyst review. The AI triage rate must never be presented as end-to-end attack detection. A model output of `Needs Review` is an abstention, not a correct attack/benign decision.

The current four preview cases are frozen in `evaluation/frozen_smoke.json` with SHA-256 hashes of the alerts, timelines, and prompt. They are **workflow smoke tests only**: all were selected because rules fired, there is no benign hard case, and no missed attack can enter this queue. They are insufficient to estimate AI sensitivity, specificity, or improvement over an analyst. Real model results from these cases may describe failures and traces but not population performance.

## Final evaluation case set (pending source data and independent review)

Before any final runs, define a separate development set for prompt and integration changes, then freeze a held-out set with a manifest of case IDs, evidence hashes, selection rules, labels, and exclusion reasons. The competition scope is PortScan, DoS and BruteForce, plus Benign-labeled controls and boundary examples. DDoS and other attack labels are out of scope and must be reported separately. Benign is an evaluation label, never an attack rule or an automatic safe verdict. Do not silently treat CIC-IDS2017's single-source DDoS-labeled groups as observed distributed traffic. Cases not raised by rules belong to an isolated AI-only harness; count them as detector misses in the end-to-end layer. Do not add them to the normal queue and imply that the detector found them.

Use the dataset label only for scoring, never in model tool output. Have two reviewers independently assess at least a subset of ambiguous cases and report agreement and disagreements; labels are imperfect. Avoid selecting cases based on the model's answers. Freeze the case set, prompts, model ID/version, parameters, scoring code, and stopping rule before the held-out run.

## Conditions

The **primary product condition** exposes the detector rule type and rule basis, as it does to the analyst. All conditions hide dataset labels and dataset-identifying file names. Optional sensitivity analyses: (a) rule-blind tools hide type and any equivalent hint in `rule_basis`, title, or summary; (b) stable replacement IPs and relative times preserve flow counts, ports, identities within a case, and time gaps; (c) prescribed tool order versus unconstrained choice within the same read-only allowlist. Compare paired cases with the same scoring rubric. A changed answer under anonymisation shows sensitivity to identity cues; it does not by itself prove training-data memorisation.

## Measurements

For each run save provider, exact model ID, temperature, prompt/data hashes, run ID, verdict, validation status, cited evidence IDs, tool sequence, tool errors, elapsed time, and whether the analyst confirmed it. Never save API keys. For attack reference cases report `Likely Benign / all attack cases`, and for benign cases `Likely Attack / all benign cases`. Report `Needs Review / all cases` separately, plus invalid-proposal rate, evidence-ID and numeric-claim validation failures, median tool calls and latency. Repeated runs of the same case are correlated: show per-case variability and do not count them as independent cases in a Wilson interval. For adequate independent case counts, report numerator/denominator with a case-level interval; for a small pilot, emphasize exact counts and examples.

The three workflow safety counters are attack/benign case merging, low-priority attack assignment, and attack-closure recommendation. Report their denominator as the number of reviewed evaluation cases, separately from rule and AI metrics. Record human confirmations of `Likely Benign` and reasons, but do not call a typed reason proof of a sound decision.

## Controls and limits

Mock-provider outputs establish software behavior only and are excluded from AI performance reporting. The current tool view exposes rule results in the product condition and sampled flows only; there is no normal-traffic context tool. Sampling is first records plus last for CIC-IDS2017, so there is position bias. Existing rule thresholds were tuned after inspecting the historical dataset, making the current 68.12% three-type recall a development-set result. The frozen smoke set is not an independent test set. A future baseline model must fit, calibrate, and test on disjoint chronological blocks with a gap, and must not be described as zero-day detection.

## Execution

The original `evaluation/frozen_smoke.json` preserves hashes for the older four-case preview and is no longer compatible with the current bundle. Run `python -m evaluation.run_live --check` to verify the current five-case **development** smoke manifest and provider without sending a model request. With a configured live Groq, Gemini, or Codex provider, run `python -m evaluation.run_live --runs 3` if repeated workflow observations are needed. This writes isolated JSON results under Git-ignored `data/evaluation/`; it does not change the app's saved triage decisions. Development smoke outputs are not independent AI accuracy results.

For a genuinely independent AI case set, create a separate alert JSON and matching timeline JSON. Before any model run, freeze a manifest with `kind: independent-ai-holdout`, their exact SHA-256 hashes, the prompt hash, case IDs, reviewer-provided `reference_labels` (`Attack`, `Benign`, or `Ambiguous`), `frozen_at`, `reviewed_by`, `source_archive_sha256`, and `development_archive_sha256` (a list). Pass those files with `--alerts`, `--timelines`, and `--manifest`. The runner rejects changed hashes, declared archive overlap, and mock providers; it records isolated tool traces and audit verification, then reports attack-to-benign and benign-to-attack counts. Hashes do not prove that cases were previously unseen; the named reviewer must verify prior exposure and label quality. Repeated runs of one case are correlated.


## Detector evaluation revision — 2026-10-23

This revision supersedes older detection rates and DDoS scope statements above. The three displayed attack rules are PortScan, DoS, and BruteForce. `NeedsReview` is an optional review heuristic, not a fourth attack rule. `No alert` means only that these rules did not fire; it must never be translated to Benign or safe. BruteForce means repeated FTP/SSH connections, not confirmed failed authentication. DoS volume does not prove service exhaustion.

### Reproduce the historical development check

```
python -m services.evaluate_detection path/to/GeneratedLabelledFlows.zip -o data/detection-evaluation-20261023.json
python -m services.alerts path/to/GeneratedLabelledFlows.zip -o data/alerts-evaluation-20261023.json
python -m services.evaluate_grouping data/alerts-evaluation-20261023.json -o evaluation/grouping-development-20261023.json
python -m unittest services.test_detection_evaluation services.test_evaluate_baseline
```

Use Python 3.11+ and `requirements-eval.txt` for baseline execution. The primary detector and evaluator use the standard library. On restricted Windows runners, set `tempfile.tempdir` to a writable workspace folder when running unittest. No live AI calls, approval actions, audit writes, or queue changes are needed. The commands above write separate evaluation artifacts; do not replace bundled UI data during this task.

The primary unit is `(source file, source IP, destination IP, calendar minute)`, using fixed 60-second buckets. Evaluate every group in the selected complete CSVs, including groups with no alert. Score only pure Benign or pure in-scope attack groups. Mixed groups, DDoS, unknown and other attack labels are explicitly excluded with counts and predicted-output counts. These exclusions limit the scope of every reported rate and must accompany it. Report the complete confusion matrix, per-class TP/FP/FN, Benign FP, wrong-attack-type predictions, and no-alert misses. Binary attack detection credits any in-scope alert on an in-scope attack; per-class scoring does not credit the wrong attack type. Benign false-positive rate is FP/(FP+TN), not 1-precision. Undefined rates are null.

Each report records the archive, detector source and evaluator SHA-256, Python version, rule thresholds, and deterministic error rows identifying every included FP/FN or wrong-type group. The error rows are offline scoring artifacts and contain labels; they are not model inputs. The same archive and code reproduce the same JSON in the same Python environment. Do not choose a preview or only alert-bearing cases for detection scoring.

### External holdout protocol

Obtain a separate, previously unused labeled flow archive with the same CSV schema. Before looking at its scores, freeze the detector and a JSON manifest with:

- `purpose`: `external_holdout`; `frozen_at`: the actual freeze timestamp.
- `detector_sha256`: SHA-256 of `services/alerts.py`.
- `archive_sha256`: SHA-256 of the complete external archive.
- `members`: exact archive member names mapped to uncompressed CSV SHA-256 values.
- `development_archive_sha256`: all archives used for rule selection.
- `development_member_sha256`: all uncompressed CSVs used for rule selection.

Run:

```
python -m services.evaluate_detection path/to/external.zip --holdout-manifest path/to/frozen-manifest.json -o data/independent-detection.json
```

The evaluator rejects changed code, changed archives/members, and declared development overlap. Hash checking verifies the manifest, not its author's historical honesty or semantically duplicated traffic; a second reviewer must verify prior exposure, traffic/session separation, label mapping, completeness and exclusions. Freeze the manifest in version control before scoring. If thresholds change after seeing results, that holdout becomes development data and a new external holdout is required. CIDDS-001 external-domain detection results are now available in evaluation/CIDDS_HOLDOUT.md. The five-case external AI diagnostic and its limited automatic label review are described in JOINT_ACCEPTANCE.md; this is not a representative expert-adjudicated benchmark. Synthetic fixtures test software correctness only.

### Case grouping contract

Group only the same source file, attack rule and ordered source/destination pair; BruteForce also requires the same target login port. Consecutive alert minute starts at most five minutes apart join one case. A chain can therefore exceed five minutes overall. Different types are separate cases with optional related-case links; links do not merge evidence. IDs include the full grouping key and starting minute. Changing this contract changes generated case IDs; regenerate alert/timeline artifacts together in a separate coordinated update rather than attaching old saved decisions to new cases. Never split or merge production cases using dataset truth labels.

The rules use first-match priority PortScan, then DoS, then BruteForce; concurrent behaviors may be masked. Fixed buckets miss slow scans, bursts across minute boundaries and low-rate guessing. Pair-based grouping can fragment campaigns and cannot establish distributed attacks. Missing authentication, service-health and legitimate-workload context prevents automatic security conclusions. Historical thresholds remain unchanged in this revision to avoid tuning against a test result.

The separate Isolation Forest baseline now uses Tuesday (including FTP/SSH), Wednesday and Friday PortScan as shifted-day comparisons, and shares the three-type scoring scope. It remains a historical experiment and is not an independent validation of the deployed rules or an automatic attack classifier.

## Joint acceptance — 2026-10-24

See [JOINT_ACCEPTANCE.md](JOINT_ACCEPTANCE.md) for reproduced detection results, the frozen five-case external AI diagnostic, 21 synthetic safety contracts, 254 passing tests and outstanding generalization limits. Do not combine development smoke, external detector recall and safety-contract pass counts into one accuracy figure.
