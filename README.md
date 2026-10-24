# SOC Desk

## Demo sign-in

The local UI opens on a single-user sign-in screen. On first use, sign in as `administrator` / `Demo@1234`, then use the account menu at the bottom of the sidebar to change that password. The local API verifies the password and protects its routes with an eight-hour, HttpOnly session cookie and CSRF checks on writes. Changing the password signs out every session. The bundled historical preview JSON remains a static frontend asset, so this local demo is not a production access-control boundary for the dataset.

The password hash is stored in Git-ignored `data/auth/account.json`, using a unique salt and scrypt. New passwords must have 15–128 characters; common choices are blocked, and five failed login or current-password attempts cause a fifteen-minute lockout. The lockout and active sessions are in this single local API process, so restarting it clears them and signs everyone out.

Alert generation, incident grouping, and timeline reconstruction use the official CIC-IDS2017 `GeneratedLabelledFlows.zip`. Suggested investigation checks, analyst decisions, case-note drafts, and audit logging run in a local Python service. The AI check can now run the merged triage agent against a case's evidence; its default mock provider is explicitly labelled as a demo simulation.

## Run the demo on Windows

Install Node.js LTS (with npm) and Python 3.10 or newer, then open the project folder and run `start.cmd`. The script installs missing frontend and Python packages, starts the local API, and opens `http://127.0.0.1:5174`. The preview data is already in `src/real-alerts.json` and `src/real-timelines.json`; the large source archives are **not** needed to open the demo. Dependencies in `node_modules/` are machine-specific and are not part of the repository.

If the frontend says `Cannot find package 'esbuild'`, run `npm install --include=optional` in the project folder and start again. If installation still fails, remove that machine's incomplete `node_modules` folder and rerun `npm install --include=optional`. Keep the terminal open while using the app; a startup error is shown there. The local API log is in `data/api.err.log`.

## Regenerate historical data (optional)

The bundled demo contains 10 CIC-IDS2017 Cases: 2 suspected brute-force, 3 DoS, 4 PortScan, and 1 unclassified review candidate. Two of the attack-rule Cases are labeled Benign in the dataset and therefore provide real false-positive review examples. To refresh the data, run from the repository root:

```powershell
python services/alerts.py path/to/GeneratedLabelledFlows.zip --include-monday-review -o src/real-alerts.json
python services/timeline.py src/real-alerts.json -o src/real-timelines.json
```

`start.cmd` starts Vite and the loopback Python review service. The frontend reads the tracked JSON files; the local review service writes `data/audit.db`. `data/` stays local and is ignored by Git. Only up to six sampled flow records per alert enter the tracked JSON; the large source archive stays local. The earlier Yatesbury DDoS demonstration is archived rather than included in this three-type queue.

## Detection and grouping

The script scans the Monday, Tuesday, Wednesday, and Friday PortScan flow CSVs. It detects one-minute source/destination groups. PortScan and DoS retain their prototype count/port rules. Suspected BruteForce requires at least 50 connections from one source to one target's FTP (21) or SSH (22) port in a minute. Flow counts cannot establish failed logins; authentication logs would be needed to confirm brute force. One unmatched high-volume Monday group becomes NeedsReview, selected without reading its label.

Consecutive alerts are grouped by type and source CSV when their gap is at most five minutes: PortScan follows the source IP, DoS follows the destination IP, and suspected BruteForce follows the source/target/login-port tuple. Different types remain separate. Rule thresholds are prototype heuristics selected during development, not independently validated SOC policy. No rule match is not a Benign verdict.

The detector does not read dataset labels when matching or grouping alerts. Labels are kept for retrospective evaluation and are withheld from model-facing tools. A normal-labeled Case does not automatically receive a Likely Benign AI verdict: the live model may reasonably return Needs Review without business context.

### Checking detection quality and extending rules

Run `python -m services.evaluate_detection path/to/GeneratedLabelledFlows.zip -o data/detection-evaluation.json` on the **complete** archive. The current results and limitations are in [THREE_TYPE_EVALUATION.md](THREE_TYPE_EVALUATION.md). The earlier [DETECTION_AUDIT.md](DETECTION_AUDIT.md) describes the archived DDoS configuration, not this queue. This is an offline historical check on data used during rule development, not a claim of live SOC accuracy.

Named rule predicates and thresholds live in `services/alerts.py`. `--include-monday-review` exports unmatched high-volume Monday groups as NeedsReview candidates (at least 500 flows and 5,000 packets in a minute); this is a coarse review heuristic, **not** zero-day detection. `--include-unclassified` applies the same rule across all included days and is not used in the bundled queue.

## Timeline

`services/timeline.py` orders sampled source records and every alert in each incident by timestamp and CSV row. Each event carries an evidence ID that resolves to a flow or alert in the matching JSON export. PortScan alerts map to MITRE ATT&CK T1046; DDoS alerts map to T1498; events without sufficient evidence are Unmapped. The source timestamps have minute precision. Friday afternoon CSV hours are normalized to afternoon according to their filename.

The Timeline view covers every minute between a case's first and last recorded event, including minutes without an exported rule match. It highlights the first match, peak matched minute, matched flow total, and linked sample count. Selecting a minute explains the detection basis and links to its alert evidence before navigating to the Evidence view. Blank minutes mean no exported rule match; the bundled preview does not include all raw network flows, so they must not be interpreted as zero traffic.

The bundled data contains 10 Cases and 159 one-minute Alerts from the four selected CIC files. Regenerate after changing any rule or dataset input.

## Archived Yatesbury DDoS case (outside the current queue)

The additional historical case uses the SYN Flood DDoS scenario's `nsg.csv` records for 2023-03-15 11:56 UTC. Three distinct sources sent 710,279 TCP records and 485,706 reported packets to 172.0.0.19 in that minute. Each source contributed more than 1,000 records. Detection uses the traffic records; `label.csv` is read afterward as a separate reference, not as the trigger. Six sampled flow IDs point back to original `nsg.csv` row numbers. This is a historical dataset replay, not live detection.

## Demo path

Open Investigations to see the case list, then open the PortScan case. The five tabs can be selected directly. Timeline shows six one-minute PortScan alerts from 14:51 through 14:56, including the 14:54 match with 34,620 records across 997 destination ports. Select a point to see its detection basis and linked flow records. The alerts group because source IP, destination IP, and source CSV match and their gap is under five minutes.

The dataset label is shown separately from the rule result. It is a reference for evaluation, not the reason the rule fired. A PortScan rule match is a candidate incident; triage and any verdict belong to the other modules. Source timestamps have only minute precision, so events within one minute are ordered by CSV row where available.

AI check displays Pending until an analyst selects **Run AI check**. The merged agent reads case evidence through allowlisted tools, validates cited evidence IDs, and stores a proposed verdict separately from analyst decisions. Numeric traffic claims must also match stored case aggregates or linked sample computations. The analyst can confirm or reject the AI proposal in the UI; confirming a protected Likely Benign proposal requires a written reason. By default `AI_PROVIDER=mock`, so its output is a **demo simulation**, not a live model assessment. For a live provider, copy `.env.example` to `.env`, set `AI_PROVIDER=groq` or `gemini` and the matching API key, then run `python -m services.preflight` before the demo. Next Steps continues to show deterministic, evidence-linked investigation checks based on rule matches. An analyst approves or rejects every check and enters a name before submitting. The local service inserts decisions into SQLite and appends AI and analyst events to one hash-chained audit table. A case-note draft is returned only when at least one check is approved. No security action is executed.

The historical AI JSONL and analyst SQLite events are imported into the new `audit_events` table on first use. The old stores are retained as read-only migration sources; new events go only to `audit_events`. SQLite triggers reject UPDATE and DELETE on that table, and the Audit page checks the hash chain. This protects against edits through this application, not an administrator who can replace the database file.

Run `python -m services.evaluate_detection path/to/GeneratedLabelledFlows.zip -o data/detection-evaluation.json` for the existing rules. Install `requirements-eval.txt`, then run `python -m services.evaluate_baseline path/to/GeneratedLabelledFlows.zip -o data/baseline-evaluation.json` for the separate, normal-only Isolation Forest experiment. It uses Monday chronological training, calibration and test blocks with five-minute gaps, then measures shifted-day Benign false positives and known-attack recall on Wednesday and Friday. Calibration and reporting use source/destination/minute groups; flagged benign cases are counted separately after a five-minute grouping. Dataset labels are excluded from model features and used only for evaluation. This baseline is **not** the deployed detector and anomaly scores are not attack verdicts. Combine reports with `python -m services.evaluate_system --detector-report data/detection-evaluation.json --baseline-report data/baseline-evaluation.json`; `--cases path/to/reviewed-cases.json` adds workflow safety counts when reviewed cases exist. Without a baseline report, the rate sweep stays pending rather than inventing results.

You can also configure live AI from **AI settings** in the sidebar: select Groq or Gemini, enter the model ID and API key, use **Test connection**, then **Save settings**. The key is stored only by the loopback Python service in `data/ai-settings.json` (Git-ignored); the browser receives only a configured/not-configured flag. Saved UI settings take precedence over `.env` and apply to the next AI check without restarting. Restart `start.cmd` once after updating the application code so the settings endpoints are available.

For **Codex CLI**, install `@openai/codex`, run `codex login` on the computer running the Python API, then choose **Codex CLI** in AI settings. Leave Model ID as `default` to use the CLI default. **Test connection** makes one real Codex request, then **Save settings** activates it. Codex investigations use the account's Codex allowance; no API key is needed. The adapter starts each model turn in a temporary read-only CLI session and passes only the case conversation and read-only tool descriptions. Existing case results remain in the local state store if the allowance is exhausted.

After a new AI check, the validated proposal may include one or two evidence-linked next investigation steps. Recommendations highlights those AI suggestions and their cited evidence, while keeping the case-rule checks available. Only allowlisted read-only steps can be approved; an analyst must approve or reject each check. Earlier stored AI results do not contain these new suggestions until checked again.

The guardrails reject evidence IDs outside the case, prevent unsupported verdicts, and require explicit analyst confirmation for a Likely Benign verdict on an attack alert. The safety evaluator separately counts attack/benign merges, low-priority attack assignments, and attack closure recommendations from a supplied evaluation-case JSON array. A zero count on a test set would not establish zero operational risk.

Run the workflow checks with `python -m unittest discover -s services -p test_workflow.py`. To evaluate a JSON array of cases with `dataset_labels`, `priority`, and `recommendations`, run `python services/guardrails.py path/to/evaluation-cases.json`.
