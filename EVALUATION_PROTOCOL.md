# SOC Desk evaluation protocol — draft frozen before live model runs

Date: 2026-10-22 (Asia/Kuala_Lumpur). This document records the intended measurement and its limits. Changing the protocol after viewing test results requires a dated revision; report both versions.

## Claims and units

Report three layers separately: (1) rule detection on all eligible source/destination/minute groups, including missed attacks; (2) AI triage *conditional on an input case existing*; (3) workflow safety after analyst review. The AI triage rate must never be presented as end-to-end attack detection. A model output of `Needs Review` is an abstention, not a correct attack/benign decision.

The current four preview cases are frozen in `evaluation/frozen_smoke.json` with SHA-256 hashes of the alerts, timelines, and prompt. They are **workflow smoke tests only**: all were selected because rules fired, there is no benign hard case, and no missed attack can enter this queue. They are insufficient to estimate AI sensitivity, specificity, or improvement over an analyst. Real model results from these cases may describe failures and traces but not population performance.

## Final evaluation case set (pending source data and independent review)

Before any final runs, define a separate development set for prompt and integration changes, then freeze a held-out set with a manifest of case IDs, evidence hashes, selection rules, labels, and exclusion reasons. Include PortScan, DoS, observed multi-source DDoS, boundary and benign high-traffic examples. Do not silently treat CIC-IDS2017's single-source DDoS-labeled groups as observed distributed traffic. Cases not raised by rules belong to an isolated AI-only harness; count them as detector misses in the end-to-end layer. Do not add them to the normal queue and imply that the detector found them.

Use the dataset label only for scoring, never in model tool output. Have two reviewers independently assess at least a subset of ambiguous cases and report agreement and disagreements; labels are imperfect. Avoid selecting cases based on the model's answers. Freeze the case set, prompts, model ID/version, parameters, scoring code, and stopping rule before the held-out run.

## Conditions

The **primary product condition** exposes the detector rule type and rule basis, as it does to the analyst. All conditions hide dataset labels and dataset-identifying file names. Optional sensitivity analyses: (a) rule-blind tools hide type and any equivalent hint in `rule_basis`, title, or summary; (b) stable replacement IPs and relative times preserve flow counts, ports, identities within a case, and time gaps; (c) prescribed tool order versus unconstrained choice within the same read-only allowlist. Compare paired cases with the same scoring rubric. A changed answer under anonymisation shows sensitivity to identity cues; it does not by itself prove training-data memorisation.

## Measurements

For each run save provider, exact model ID, temperature, prompt/data hashes, run ID, verdict, validation status, cited evidence IDs, tool sequence, tool errors, elapsed time, and whether the analyst confirmed it. Never save API keys. For attack reference cases report `Likely Benign / all attack cases`, and for benign cases `Likely Attack / all benign cases`. Report `Needs Review / all cases` separately, plus invalid-proposal rate, evidence-ID and numeric-claim validation failures, median tool calls and latency. Repeated runs of the same case are correlated: show per-case variability and do not count them as independent cases in a Wilson interval. For adequate independent case counts, report numerator/denominator with a case-level interval; for a small pilot, emphasize exact counts and examples.

The three workflow safety counters are attack/benign case merging, low-priority attack assignment, and attack-closure recommendation. Report their denominator as the number of reviewed evaluation cases, separately from rule and AI metrics. Record human confirmations of `Likely Benign` and reasons, but do not call a typed reason proof of a sound decision.

## Controls and limits

Mock-provider outputs establish software behavior only and are excluded from AI performance reporting. The current tool view exposes rule results in the product condition and sampled flows only; there is no normal-traffic context tool. Sampling is first records plus last for CIC-IDS2017, so there is position bias. Existing rule thresholds were tuned after inspecting the historical dataset, making its 43.9% rule recall a development-set result. The frozen smoke set is not an independent test set. A future baseline model must fit, calibrate, and test on disjoint chronological blocks with a gap, and must not be described as zero-day detection.

## Execution

Run `python -m evaluation.run_live --check` to verify the frozen smoke input and current provider without sending a model request. After configuring a *live* Groq or Gemini provider in AI settings, run `python -m evaluation.run_live --runs 3`. This writes isolated JSON results under Git-ignored `data/evaluation/`; it does not change the app's saved triage decisions. Do not submit those four-case outputs as AI accuracy results.
