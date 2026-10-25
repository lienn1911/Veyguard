# Veyguard

**Evidence-linked AI triage for network security alerts.**

Veyguard brings related alerts, supporting records and human review into one case workspace. It helps security analysts understand why activity was flagged, examine an AI assessment and decide what to investigate next.

This is a local prototype using historical CIC-IDS2017 network-flow data. The bundled demonstration contains **9 cases** covering **PortScan, DoS and suspected BruteForce**. It is not a live network monitor or an autonomous response system.

## Contents

- [Quick start](#quick-start)
- [Configure AI analysis](#configure-ai-analysis)
- [Review your first case](#review-your-first-case)
- [Understand decisions and saved reports](#understand-decisions-and-saved-reports)
- [Data and storage](#data-and-storage)
- [Project structure](#project-structure)
- [Troubleshooting](#troubleshooting)
- [Limitations](#limitations)
- [Development and evaluation](#development-and-evaluation)

## Quick start

### Requirements

- Node.js with npm; use an LTS release compatible with Vite 6.
- Python 3.10 or newer, available as `python`.
- Git, if cloning the repository.
- A configured AI provider for real AI analysis.

### Windows

```powershell
git clone https://github.com/lienn1911/Veyguard.git
cd Veyguard
.\start.cmd
```

The launcher installs missing dependencies, starts the Python API and opens **http://127.0.0.1:5174**. Keep the frontend terminal open while using the application.

The bundled cases are included: you do not need to download the original dataset to explore them. All original communication records require the optional import described under [Data and storage](#data-and-storage).

### Manual startup

From the repository root, install dependencies:

```powershell
npm install --include=optional
python -m pip install -r requirements.txt
```

Start the backend in one terminal:

```powershell
python -m services.api
```

Start the frontend in another terminal:

```powershell
npm run dev -- --port 5174 --strictPort
```

Open **http://127.0.0.1:5174**. The current review API listens on **127.0.0.1:8765**; Vite forwards `/api` requests to it.

### First sign-in

| Field | Initial value |
| --- | --- |
| Username | `administrator` |
| Password | `Demo@1234` |

These credentials initialise a new local installation. Use the account menu at the bottom of the sidebar to change the password. Replacement passwords require 15–128 characters. Changing the password signs out existing sessions.

The application currently uses one local account. It does not provide multi-user account administration.

## Configure AI analysis

1. Open **AI settings** in the sidebar.
2. Select an available provider, enter its model ID and required credentials.
3. Select **Test connection**, then **Save settings**.
4. Open a case from **Investigations**.

The current adapters support Groq, Gemini and a locally authenticated Codex CLI. Codex CLI requires installation and sign-in on the computer running the backend. Connection tests can make a real model request and consume provider allowance.

Alternatively, copy `.env.example` to `.env` and configure a supported provider there. Saved settings from the interface take precedence over environment settings.

**The default `mock` provider is for deterministic software tests.** It does not provide a genuine AI assessment in the normal review interface. Configure a live provider to use AI analysis. Relevant case evidence is sent to that provider when an investigation runs; review its data-handling requirements before using your own records.

API keys stay in backend configuration and are not returned to the browser. Local `.env` and `data/` files are Git-ignored.

## Review your first case

### 1. Choose a case

Open **Investigations**. Search or filter the case list, check its AI and review status, then open a case.

Opening a case requests AI analysis when a live provider is configured and no reusable valid result exists. Human review is still required.

Review priority helps order the queue. **High, Medium and Low are activity-based review priorities, not confirmed attack severity.**

### 2. Understand the Overview

The **Overview** shows the communication path, observation period, alert count, matched flow count and **Why flagged** explanation. The AI assessment provides a short conclusion and expandable analysis details.

| AI conclusion | Meaning |
| --- | --- |
| Likely Attack | The AI considers the available evidence consistent with attack activity; analyst verification is required. |
| Likely Benign | The AI considers a legitimate explanation more likely; it is not automatic clearance. |
| Needs Review | The available evidence is insufficient for a stronger conclusion. |

AI confidence is model-reported and is not a calibrated probability of an attack.

### 3. Inspect the Timeline and evidence

Open **Timeline** to inspect minute-level activity, detection reasons and rule criteria. Click an evidence reference to jump to its corresponding record. Expand communication records when you need the underlying detail.

The bundled samples provide traceable examples. Browsing all original records requires the local raw-flow database. A minute without a rule match is not proof of benign activity.

### 4. Review Recommendations

Read each proposed step and expand **Reason and evidence** when needed. Choose **Approve** or **Reject**, add a remark where useful, then select **Save decisions**.

Approval records an agreed next step. Find these under **Home → Approved next steps** and open a linked case to review its evidence and approval remarks. Actual investigation takes place outside Veyguard. Veyguard does not block traffic, isolate a device or perform the recommended investigation for you.

### 5. Record findings and review the AI conclusion

Use **Notes** in the case header while examining any case tab. Record what you checked and found, optionally attach an evidence ID, then save the note. The evidence selector supports search.

In **Triage report → AI assessment**, choose **Agree** or **Disagree**. Disagreement requires a reason. Accepting a protected Likely Benign result also requires written justification. Saved decisions show the reviewer and time.

### 6. Save or download the report

Review the report's assessment, evidence, investigation steps, notes and activity history. Select **Save report** to preserve the current snapshot, or **Download PDF** for a complete black-and-white document.

To revisit a saved report, use the **Report saved** filter in Investigations, open the case and select **Triage report**. PDF export uses the stored snapshot when a saved report exists; otherwise it exports the current draft.

## Understand decisions and saved reports

| Item | Purpose |
| --- | --- |
| Investigation note | Records what you checked and found; optionally links to evidence. |
| Recommendation remark | Explains an individual step's approval or rejection. |
| Agree / Disagree | Records your judgment about the AI conclusion. |
| Review status | Shows whether the current AI conclusion and all proposed steps have been reviewed. |
| Save report | Preserves the findings and decisions as a snapshot. |
| Download PDF | Exports the report without approving steps or saving a new snapshot. |

**Saving a report does not mark the review complete or resolve the case.** Review completion does not verify that follow-up investigation has been carried out.

The current prototype retains one saved snapshot per case. Later notes and decisions do not update that snapshot, and saving again does not create a new report version. Finish the review and save the notes you want included before saving the report.

## Data and storage

The repository includes historical cases, alerts, sampled flows and timeline context. Your local decisions, notes, credentials and AI state are stored under `data/`. Preserve this directory if you want to keep your local work; a fresh clone does not include it.

| Location | Contents |
| --- | --- |
| `src/real-alerts.json` | Bundled cases, alerts and sampled flow evidence |
| `src/real-timelines.json` | Reconstructed timeline events |
| `src/raw-context.json` | Minute-level context around case windows |
| `data/audit.db` | Review decisions, notes and shared audit events |
| `data/raw-flows.db` | Optional original-record import |
| `data/auth/` | Local account configuration |
| `data/ai-settings.json` | Provider settings saved through the interface |

### Optional: import original communication records

Obtain the CIC-IDS2017 `GeneratedLabelledFlows.zip` archive, then run:

```powershell
python -m services.raw_flows "C:\path\to\GeneratedLabelledFlows.zip"
```

This creates the local raw-flow database used for paginated record browsing. The source archive and imported database stay local.

## Project structure

```text
Veyguard/
├── src/
│   ├── components/       # Case workspace, notes, reports and settings
│   ├── modules/          # Timeline and recommendation views
│   ├── lib/              # Shared formatting and data helpers
│   ├── App.jsx           # Application entry and navigation
│   └── *.json            # Bundled historical demonstration data
├── services/             # Python API, AI tools, validation and persistence
│   ├── providers/        # AI provider adapters
│   ├── api.py            # Local review API
│   ├── triage.py         # Bounded AI investigation workflow
│   └── report_pdf.py     # Monochrome report export
├── tests/                # Automated regression checks
├── evaluation/           # Evaluation scripts and recorded results
├── reports/              # Supporting documents and review artifacts
├── scripts/              # Local startup helpers
├── data/                 # Local runtime state; Git-ignored
├── .env.example          # Backend configuration template
├── requirements.txt      # Python dependencies
├── package.json          # Frontend dependencies and commands
└── start.cmd             # Windows launcher
```

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| Frontend reports an API error | Start the Python backend; check `data/api.err.log` when using the launcher. |
| AI shows Setup needed | Configure a live provider in AI settings, test it and save the settings. |
| AI fails or reaches a usage limit | Check provider credentials and allowance; retry when available. Failures are not replaced with simulated conclusions. |
| Original communication records are unavailable | Import the source archive into `data/raw-flows.db`. Bundled samples remain available. |
| `Cannot find package 'esbuild'` | Run `npm install --include=optional`, then restart. |
| Port 5174 or 8765 is occupied | Stop the conflicting service before starting the application. |
| Recent backend changes are missing | Restart the application; refreshing the browser alone does not restart Python. |
| Signed out after a restart | Sessions are local to the API process; sign in again. |

## Limitations

- The prototype replays historical data; it does not ingest live network traffic.
- Detection rules have limited cross-dataset generalisation. Missed attacks do not reach the normal AI queue.
- Flow records alone cannot confirm failed authentication, successful compromise or service disruption.
- Evidence validation checks selected claims and citations, not every part of AI reasoning.
- ATT&CK suggestions are tentative mappings, not proof that an attack occurred.
- The local sign-in does not protect the bundled static dataset as a production access-control boundary.
- Append-only audit protections and hash verification do not prevent a local administrator from replacing storage.
- GitHub Pages alone cannot run the Python API, AI analysis or persistent review workflow. This repository is not itself a hosted live demo.

## Development and evaluation

For the source layout, code style and formatting commands, see the [development guide](docs/DEVELOPMENT.md).

Build the frontend:

```powershell
npm run build
```

Run automated checks:

```powershell
python -m pytest tests services evaluation -q
```

To regenerate the bundled historical data, run these together from the repository root:

```powershell
python services/alerts.py "C:\path\to\GeneratedLabelledFlows.zip" -o src/real-alerts.json
python services/timeline.py src/real-alerts.json -o src/real-timelines.json
python -m services.raw_context "C:\path\to\GeneratedLabelledFlows.zip" src/real-alerts.json -o src/raw-context.json
```

Regeneration may change case IDs. Existing local decisions remain attached to their original cases and are not transferred automatically.

For methodology, recorded checks and detection limitations, see [THREE_TYPE_EVALUATION.md](THREE_TYPE_EVALUATION.md), [JOINT_ACCEPTANCE.md](JOINT_ACCEPTANCE.md) and [FINAL_ACCEPTANCE.md](FINAL_ACCEPTANCE.md). These are technical records; workflow tests and selected AI examples do not establish operational accuracy or time savings.
