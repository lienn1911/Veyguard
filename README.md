# SOC Desk

## Demo sign-in

The local UI opens on a demo sign-in screen. Use `administrator` / `Demo@1234`. The demo session lasts for the current browser session. Use the account menu at the bottom of the sidebar to sign out. This is a UI demonstration only: the sample data is bundled with the frontend and the local API is not protected by this sign-in.

Alert generation, incident grouping, and timeline reconstruction use the official CIC-IDS2017 `GeneratedLabelledFlows.zip`. Suggested investigation checks, analyst decisions, case-note drafts, and audit logging run in a local Python service. The AI check can now run the merged triage agent against a case's evidence; its default mock provider is explicitly labelled as a demo simulation.

## Run the demo on Windows

Install Node.js LTS (with npm) and Python 3.10 or newer, then open the project folder and run `start.cmd`. The script installs missing frontend and Python packages, starts the local API, and opens `http://127.0.0.1:5174`. The preview data is already in `src/real-alerts.json` and `src/real-timelines.json`; the large source archives are **not** needed to open the demo. Dependencies in `node_modules/` are machine-specific and are not part of the repository.

If the frontend says `Cannot find package 'esbuild'`, run `npm install --include=optional` in the project folder and start again. If installation still fails, remove that machine's incomplete `node_modules` folder and rerun `npm install --include=optional`. Keep the terminal open while using the app; a startup error is shown there. The local API log is in `data/api.err.log`.

## Regenerate historical data (optional)

To rebuild the bundled preview from source archives, place `GeneratedLabelledFlows.zip` and the Yatesbury scenario archive in `data/`, then run from the repository root:

```powershell
python services/alerts.py data/GeneratedLabelledFlows.zip -o data/alerts-full.json
python services/alerts.py --preview-from data/alerts-full.json --preview-cases 3 -o src/real-alerts.json
python services/timeline.py data/alerts-full.json -o data/timelines-full.json
python services/timeline.py src/real-alerts.json -o src/real-timelines.json
python -m services.yatesbury data/normal_synflood_ddos.tar.gz --alerts-output src/real-alerts.json --timelines-output src/real-timelines.json
```

`start.cmd` starts Vite and the loopback Python review service. The frontend reads the tracked preview JSON files; the local review service writes `data/audit.db`. `data/` stays local and is ignored by Git. The Yatesbury command needs the single `normal_synflood_ddos.tar.gz` scenario from [Microsoft Yatesbury](https://github.com/microsoft/Yatesbury), not the full collection. Run it after regenerating the CIC-IDS2017 preview. It replaces its own case on repeat runs. The original 163 MB archive stays local; only sampled evidence enters the tracked preview JSON.

## Detection and grouping

The script scans the Wednesday DoS, Friday DDoS, and Friday PortScan flow CSVs inside the archive. It detects one-minute flow groups using source IP, destination IP, port counts, flow counts, and packet counts. A PortScan candidate needs at least 100 destination ports and 100 flows, plus either twice as many source ports as destination ports or at least 250 destination ports and two source ports. The second branch catches dense scans that reuse source ports. A DoS candidate needs at least 1,000 flows, 10,000 packets, 10 source ports, and at most 10 destination ports. Three visible flood sources against one destination in the same minute produce DDoS rule matches.

Consecutive alerts with the same source IP, destination IP, and source CSV are grouped into one incident when their gap is at most five minutes. This turns multiple one-minute alerts into a single evidence-linked case. Rule thresholds are prototype heuristics, not validated SOC policy. No rule match is not a Benign verdict.

The detector does not read dataset labels when matching or grouping alerts. Labels are kept for evaluation and for choosing representative preview cases. In this dataset, the DDoS attack exposes one visible source IP, so its flood alerts remain DoS rule matches with a separate DDoS dataset reference. This does not establish distributed origins from the available fields.

### Checking detection quality and extending rules

Run `python -m services.evaluate_detection data/GeneratedLabelledFlows.zip -o data/detection-evaluation.json` on the **complete** archive. The report compares each source/destination/minute group's rule result with its dataset label and shows attack-detection and per-type confusion tables. Mixed-label groups are reported separately rather than forced into one truth class. The chosen preview cases cannot be used for this evaluation: they were selected because they matched the rules. The measured results and limitations are in [DETECTION_AUDIT.md](DETECTION_AUDIT.md). This is an offline historical check, not a claim of live SOC accuracy. For stronger validation, repeat on an independent dataset or traffic capture, inspect false positives and missed groups, then tune thresholds only on separate development data before rerunning the held-out check.

Named rule predicates and thresholds live in `services/alerts.py` (`DETECTION_RULES` and `RULE_THRESHOLDS`). A new evidence-backed type can be added there without changing the case grouping or evidence-linking code. Regenerate the alert and timeline exports after a rule change. Optional `--include-unclassified` exports high-volume unmatched groups as `NeedsReview` candidates (at least 500 flows and 5,000 packets in a minute); this is a coarse review heuristic with potentially many false positives, **not** zero-day detection. The Alerts filter picks up types present in the export automatically. This option is off for the current preview until its false-positive rate is measured.

## Timeline

`services/timeline.py` orders sampled source records and every alert in each incident by timestamp and CSV row. Each event carries an evidence ID that resolves to a flow or alert in the matching JSON export. PortScan alerts map to MITRE ATT&CK T1046; DDoS alerts map to T1498; events without sufficient evidence are Unmapped. The source timestamps have minute precision. Friday afternoon CSV hours are normalized to afternoon according to their filename.

The CIC-IDS2017 preview selects three incidents. The Yatesbury import adds a fourth, independently sourced DDoS incident. The CIC-IDS2017 full export currently contains six incidents and 54 one-minute alerts from its three scanned files; regenerate after changing any rule or dataset input.

## Yatesbury DDoS case

The additional historical case uses the SYN Flood DDoS scenario's `nsg.csv` records for 2023-03-15 11:56 UTC. Three distinct sources sent 710,279 TCP records and 485,706 reported packets to 172.0.0.19 in that minute. Each source contributed more than 1,000 records. Detection uses the traffic records; `label.csv` is read afterward as a separate reference, not as the trigger. Six sampled flow IDs point back to original `nsg.csv` row numbers. This is a historical dataset replay, not live detection.

## Demo path

Open Investigations to see the case list, then open the PortScan case. The five tabs can be selected directly. Timeline shows six one-minute PortScan alerts from 14:51 through 14:56, including the 14:54 match with 34,620 records across 997 destination ports. Select a point to see its detection basis and linked flow records. The alerts group because source IP, destination IP, and source CSV match and their gap is under five minutes.

The dataset label is shown separately from the rule result. It is a reference for evaluation, not the reason the rule fired. A PortScan rule match is a candidate incident; triage and any verdict belong to the other modules. Source timestamps have only minute precision, so events within one minute are ordered by CSV row where available.

AI check displays Pending until an analyst selects **Run AI check**. The merged agent reads case evidence through allowlisted tools, validates cited evidence IDs, and stores a proposed verdict separately from analyst decisions. By default `AI_PROVIDER=mock`, so its output is a **demo simulation**, not a live model assessment. For a live provider, copy `.env.example` to `.env`, set `AI_PROVIDER=groq` or `gemini` and the matching API key, then run `python -m services.preflight` before the demo. Next Steps continues to show deterministic, evidence-linked investigation checks based on rule matches. An analyst approves or rejects every check and enters a name before submitting. The local service inserts decisions and audit events into SQLite and returns a case-note draft only when at least one check is approved. No security action is executed.

The guardrails reject evidence IDs outside the case, prevent unsupported verdicts, and require explicit analyst confirmation for a Likely Benign verdict on an attack alert. The safety evaluator separately counts attack/benign merges, low-priority attack assignments, and attack closure recommendations from a supplied evaluation-case JSON array. A zero count on a test set would not establish zero operational risk.

Run the workflow checks with `python -m unittest discover -s services -p test_workflow.py`. To evaluate a JSON array of cases with `dataset_labels`, `priority`, and `recommendations`, run `python services/guardrails.py path/to/evaluation-cases.json`.
