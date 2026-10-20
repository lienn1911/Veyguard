# SOC Triage

Alert generation, incident grouping, and timeline reconstruction use the official CIC-IDS2017 `GeneratedLabelledFlows.zip`. Suggested investigation checks, analyst decisions, case-note drafts, and audit logging run in a local Python service. AI triage remains a separate integration point and does not yet issue verdicts.

## Run

Place the archive in `data/`, then run from the repository root:

```powershell
python services/alerts.py data/GeneratedLabelledFlows.zip -o data/alerts-full.json
python services/alerts.py --preview-from data/alerts-full.json --preview-cases 3 -o src/real-alerts.json
python services/timeline.py data/alerts-full.json -o data/timelines-full.json
python services/timeline.py src/real-alerts.json -o src/real-timelines.json
npm install
start.cmd
```

`start.cmd` starts Vite and the loopback Python review service. The frontend reads the tracked preview JSON files; the local review service writes `data/audit.db`. `data/` stays local and is ignored by Git. `data/alerts-full.json` and `data/timelines-full.json` contain every matched alert and grouped incident from the three selected CSV files. Both exports retain up to six source-flow records per alert, rather than copying every raw flow.

## Detection and grouping

The script scans the Wednesday DoS, Friday DDoS, and Friday PortScan flow CSVs inside the archive. It detects one-minute flow groups using source IP, destination IP, port counts, flow counts, and packet counts. A PortScan candidate needs at least 100 destination ports, 100 flows, and twice as many source ports as destination ports. A DoS candidate needs at least 1,000 flows, 10,000 packets, 10 source ports, and at most 10 destination ports. Three visible flood sources against one destination in the same minute produce DDoS rule matches.

Consecutive alerts with the same source IP, destination IP, and source CSV are grouped into one incident when their gap is at most five minutes. This turns multiple one-minute alerts into a single evidence-linked case. Rule thresholds are prototype heuristics, not validated SOC policy. No rule match is not a Benign verdict.

The detector does not read dataset labels when matching or grouping alerts. Labels are kept for evaluation and for choosing representative preview cases. In this dataset, the DDoS attack exposes one visible source IP, so its flood alerts remain DoS rule matches with a separate DDoS dataset reference. This does not establish distributed origins from the available fields.

## Timeline

`services/timeline.py` orders sampled source records and every alert in each incident by timestamp and CSV row. Each event carries an evidence ID that resolves to a flow or alert in the matching JSON export. PortScan alerts map to MITRE ATT&CK T1046; DDoS alerts map to T1498; events without sufficient evidence are Unmapped. The source timestamps have minute precision. Friday afternoon CSV hours are normalized to afternoon according to their filename.

The preview selects three incidents for the UI. The full export currently contains four incidents and 45 one-minute alerts from the scanned files; regenerate after changing any rule or dataset input.

## Demo path

Open Alert Review to see the case list, then open the PortScan case. The five tabs can be selected directly. Activity shows example records from the 79,030 observed traffic records; Why flagged shows two one-minute matches (14:54 and 14:55), including the first match's 34,620 records across 997 destination ports; Event order arranges the examples and both alerts by time. Open a record to see its source ID and technical provenance. The alerts group because source IP, destination IP, and source CSV match and their gap is under five minutes.

The dataset label is shown separately from the rule result. It is a reference for evaluation, not the reason the rule fired. A PortScan rule match is a candidate incident; triage and any verdict belong to the other modules. Source timestamps have only minute precision, so events within one minute are ordered by CSV row where available.

AI Triage displays Pending rather than inventing a verdict. Next Steps shows deterministic, evidence-linked investigation checks based on rule matches. An analyst approves or rejects every check and enters a name before submitting. The local service inserts decisions and audit events into SQLite and returns a case-note draft only when at least one check is approved. No security action is executed.

The guardrails reject evidence IDs outside the case, prevent unsupported verdicts, and require explicit analyst confirmation for a Likely Benign verdict on an attack alert. The safety evaluator separately counts attack/benign merges, low-priority attack assignments, and attack closure recommendations from a supplied evaluation-case JSON array. A zero count on a test set would not establish zero operational risk.

Run the workflow checks with `python -m unittest discover -s services -p test_workflow.py`. To evaluate a JSON array of cases with `dataset_labels`, `priority`, and `recommendations`, run `python services/guardrails.py path/to/evaluation-cases.json`.
