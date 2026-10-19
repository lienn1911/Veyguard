# SOC Triage

This working preview implements alert generation/grouping and deterministic timeline reconstruction. The other three feature modules remain unimplemented.

## Run

Place `GeneratedLabelledFlows.zip` from the official CIC-IDS2017 CSV distribution in `data/`. The archive stays local and is ignored by Git. Run from the repository root:

```powershell
python services/alerts.py data/GeneratedLabelledFlows.zip -o src/real-alerts.json
python services/timeline.py src/real-alerts.json -o src/real-timelines.json
npm install
npm run dev
```

Open the local address printed by Vite. `start.cmd` starts the frontend after dependencies are installed.

The alert script reads the Wednesday DoS, Friday DDoS, and Friday PortScan CSVs inside the archive. It groups flows by source IP, destination IP, and one-minute window. PortScan requires at least 100 destination ports, 10 source ports, and 100 flows; DoS requires at least 1,000 flows and 10,000 packets. DDoS requires at least three distinct sources hitting the same destination in the same minute. These are transparent prototype thresholds, not validated SOC policy. No rule match is not a Benign verdict.

The frontend shows selected full groups and six source-flow records at most per group. Each flow has a stable evidence ID, source filename, and CSV row. Dataset labels are reference data only; rules never read them when deciding a match. The source timestamps have minute precision. The Friday afternoon CSV files use 12-hour times without AM/PM, so their hours are normalized to afternoon according to their filename.

The DDoS rule requires at least three distinct visible source IPs with flood matches against one destination in the same minute. In this archive, the DDoS-labeled preview exposes one source IP, so it remains a DoS rule match and is marked **DDoS dataset reference**. That label is useful for evaluation but does not prove distributed origins from these CSV fields.

## Structure

```text
src/components/AlertReview.jsx   Shared review screen
src/modules/alerts.jsx           Alert-generation UI
src/modules/timeline.jsx         Timeline UI
services/alerts.py               Real CSV ingestion, rules, grouping
services/timeline.py             Evidence-linked event ordering
data/                            Local dataset archive (ignored)
```

Generated preview JSON is tracked for teammates who do not yet have the large archive. Regenerate it with the two Python commands above after changing a rule. The preview includes three DDoS-labeled flow groups for comparison; it is not a complete export of every matching flow.
