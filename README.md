# SOC Triage

A three-module SOC console over CIC-IDS2017 network flows: rule-based alert
generation and grouping (Module 1), an evidence-grounded AI triage agent
(Module 2), deterministic timeline reconstruction (Module 3), with a React
analyst console (Module 6). Modules 4 (recommendations / approval) and 5
(safe-closure guardrail) are integration points that are not implemented yet;
the UI and API say so explicitly instead of simulating them.

## Modules

| Module | Owner | Location | Status |
| ------ | ----- | -------- | ------ |
| 1 - Alert generation and grouping | teammate | `services/alerts.py` | working |
| 2 - AI incident triage | this module | `services/triage.py`, `services/tools.py`, `services/providers/` | working (mock + live adapters) |
| 3 - Timeline reconstruction | teammate | `services/timeline.py` | working |
| 4 - Recommendations / approval / audit | teammate | `services/recommendations.py` | **not connected** (probe + UI notice in place) |
| 5 - Safe-closure guardrail | teammate | `services/guardrails.py` | **not connected** (bridge + local fallback enforced) |
| 6 - Frontend | this module | `src/` | working |

## Quick start

```powershell
# 1. Python backend (from the repository root)
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
copy .env.example .env          # AI_PROVIDER=mock works without any key
python -m services.api          # http://127.0.0.1:8000

# 2. Frontend (second terminal)
npm install
npm run dev                     # http://127.0.0.1:5173 (proxies /api to :8000)
```

If the API is not running the frontend still works in an offline preview built
from the committed Module 1/3 output (`src/real-alerts.json`,
`src/real-timelines.json`), with AI triage disabled and a visible banner.

## Dataset

Place `GeneratedLabelledFlows.zip` from the official CIC-IDS2017 CSV
distribution in `data/`. The archive stays local and is ignored by Git.
Regenerate the preview artefacts after changing a rule:

```powershell
python services/alerts.py data/GeneratedLabelledFlows.zip -o src/real-alerts.json
python services/timeline.py src/real-alerts.json -o src/real-timelines.json
```

The alert script reads the Wednesday DoS, Friday DDoS, and Friday PortScan CSVs
inside the archive and groups flows by source IP, destination IP, and one-minute
window. PortScan requires 100 destination ports, 10 source ports, and 100
flows; DoS requires 1,000 flows and 10,000 packets; DDoS requires three
distinct sources against one destination in the same minute. These are
transparent prototype thresholds, not validated SOC policy. No rule match is
not a Benign verdict.

The DDoS rule requires three distinct visible source IPs; in this archive the
DDoS-labeled preview exposes one source IP, so those groups remain DoS rule
matches and are marked **DDoS dataset reference**. That label is useful for
evaluation but does not prove distributed origins from these CSV fields.

## AI providers (Module 2)

`AI_PROVIDER` selects one of `groq` | `gemini` | `mock`. Switching is a config
change only - the investigation loop, tools, validation, and UI are
provider-agnostic. There is no automatic failover: a misconfigured provider
returns an explicit error rather than silently switching models.

| Provider | Config | Notes |
| -------- | ------ | ----- |
| GroqCloud (primary) | `GROQ_API_KEY`, `GROQ_MODEL=openai/gpt-oss-20b` | OpenAI-compatible tool calling; verify the model id with the pre-flight check |
| Google Gemini (secondary) | `GEMINI_API_KEY`, `GEMINI_MODEL=gemini-2.5-flash-lite` | `functionDeclarations` adapter, schema subset projected automatically |
| Mock | `AI_PROVIDER=mock` (no key) | Deterministic stand-in that runs the real loop, tools, validation and audit trail offline. Used for the demo and for tests. |

The models listed are free-tier candidates, not guarantees. After adding a key
run:

```powershell
python -m services.preflight
```

It checks that the key is accepted, that the configured model is visible to the
account, and that the model actually emits tool calls. Exit code 0 means live
mode is ready.

Keys live only in `.env` (git-ignored; see `.env.example`). The API never
returns them: `/api/health` reports whether a key is configured, not its value.
The browser talks only to the Python API (via the Vite proxy in dev); no LLM
call happens from the frontend.

## How the triage agent works

1. `POST /api/incidents/{id}/triage` starts a bounded investigation.
2. The agent may call exactly four read-only tools: `get_incident_details`,
   `get_related_alerts`, `get_network_flows`, `get_incident_statistics`.
   Unknown tools are blocked, arguments are schema-validated, and calls are
   scoped to the incident under investigation.
3. CIC-IDS2017 ground-truth labels are stripped from everything the model sees;
   classification must come from observed flow behaviour and Module 1's rule
   output.
4. The model answers with a JSON proposal (`incident_id`, `verdict`,
   `confidence`, `reason`, `evidence_ids`, `findings`, `limitations`).
5. Deterministic backend validation rejects: mismatched incidents, invalid
   verdicts, unknown/foreign evidence IDs, empty evidence for attack/benign
   verdicts, statistics that never appeared in tool output, and answers
   produced without any tool call. One bounded repair attempt is allowed.
6. Outcomes are separated: `ok` (validated proposal), `rejected` (validation
   failure - verdict is forced to Needs Review and clearly labelled as *not a
   classification*), `error` (provider/timeout/step limit - no verdict at all).
7. Guardrails: a `Likely Benign` proposal on a PortScan/DoS/DDoS incident
   requires an explicit analyst decision (`POST .../decision`). Proposals and
   decisions are stored separately. The agent has no write tools.
8. Every run, tool call, and analyst decision is appended to a hash-chained
   audit trail (`data/audit/triage-audit.jsonl`, verified via `/api/audit`).
   Module 4 owns the project-wide audit log; this stream is designed to merge.

## API

Base URL `http://127.0.0.1:8000` (CORS restricted to the configured Vite
origins). Errors are `{"error": {"code", "message"}}`.

```
GET  /api/health                                     service + AI status, no secrets
GET  /api/dataset                                    provenance, rules, counts
GET  /api/incidents                                  list + triage state
GET  /api/incidents/{id}                             detail + evidence + timeline
GET  /api/incidents/{id}/evidence                    sampled flow records
GET  /api/incidents/{id}/timeline                    Module 3 output
GET  /api/incidents/{id}/triage                      last stored proposal
POST /api/incidents/{id}/triage                      run the investigation
POST /api/incidents/{id}/decision                    analyst confirms/rejects
GET  /api/incidents/{id}/recommendations             Module 4 probe (501 until connected)
POST /api/incidents/{id}/recommendations/{rid}/approve
GET  /api/audit                                      append-only trail + chain check
GET  /api/settings                                   provider matrix + integrations
```

## Tests

```powershell
python -m pytest          # or: npm test
```

128 tests, no network or API key required (providers are scripted /
`httpx.MockTransport`). Coverage includes: PortScan / DoS / benign /
insufficient-evidence classifications, missing and fabricated evidence, foreign
evidence, invalid verdicts, malformed JSON, unsupported statistics, provider
timeout and rate limiting, failed and invalid tool calls, unauthorized tools,
bounded loops and tool budgets, the no-tool-use nudge, guardrail escalation,
audit tamper detection, adapter wire formats for Groq and Gemini, and
provider-parity of the result schema.

## Teammate integration points

* **Module 5** - expose one of `evaluate_proposal` / `assess_proposal` /
  `requires_human_confirmation` in `services/guardrails.py` with the contract
  documented in `services/guardrail_bridge.py`. The bridge picks it up
  automatically; it can weaken nothing (the local rule stays as a floor).
* **Module 4** - expose `get_recommendations` (or `recommend_next_steps`) in
  `services/recommendations.py`; the API and UI light up automatically.
  Approval stays disabled until Module 4 defines an approval endpoint.

## Frontend structure

```text
src/components/   Dashboard, AlertReview (incident review), EvidencePanel, AuditLog, Sidebar, Icon
src/modules/      alerts (incident list), triage (AI panel), timeline, recommendations, guardrails
src/lib/          api client, bundled offline fallback, formatting helpers
```

The incident list supports search, verdict filtering, and sorting; evidence
IDs anywhere in the UI open the underlying record; the AI triage panel shows
the verdict, cited evidence, findings, limitations, the investigation trace
(including blocked tool attempts), and the analyst decision form.
