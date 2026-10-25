# Development guide

## Project layout

```text
Veyguard/
├── src/                         React application
│   ├── App.jsx                  Session, navigation and global search
│   ├── components/              Page views and shared controls
│   │   └── animated-icons/      Vendored icons and upstream license
│   ├── modules/                 Timeline and recommendation views
│   ├── lib/                     API and formatting helpers
│   └── *.json                   Historical demonstration evidence
├── services/                    Python backend
│   ├── api.py                   Local review API
│   ├── ai_api.py                Separate FastAPI AI interface
│   ├── case_analysis.py         Case investigation concurrency control
│   ├── triage.py                AI investigation workflow
│   ├── providers/               AI provider adapters
│   ├── recommendations.py       Suggested steps and analyst decisions
│   ├── unified_audit.py         Append-only audit storage and verification
│   └── report_pdf.py            Monochrome report export
├── tests/                       Regression tests
├── evaluation/                  Evaluation and isolated acceptance tools
├── scripts/                     Windows service startup helper
├── docs/                        Contributor documentation
├── pitchdeck/                   Presentation source
├── reports/                     Reports and supporting artifacts
├── data/                        Local runtime state, ignored by Git
└── dist/                        Generated frontend build
```

Keep module paths stable: launchers, test tools and evaluation records refer to them.
Historical evidence and evaluation outputs are not source files to reformat.

## Install development tools

Install Node.js with npm and Python 3.10 or newer. From the repository root:

```powershell
npm install --include=optional
python -m pip install -r requirements-dev.txt
```

The repository also provides `pnpm-lock.yaml` for pnpm users. When updating dependencies,
keep that lockfile current.

## Code style

- JavaScript, JSX, CSS and HTML: Prettier, two spaces and a 100-character preferred width.
- Python: Ruff formatter, four spaces and a 100-character preferred width.
- Text files: UTF-8 and a final newline.
- Windows shell scripts: retain CRLF line endings.
- Vendored icons retain their upstream formatting and license.

Run formatting:

```powershell
npm run format
```

Check formatting without editing files:

```powershell
npm run format:check
```

Use `format:web` or `format:python` to format only one language group.
These commands skip dependencies, runtime data, reports, generated builds and bundled
historical JSON files. PowerShell and batch scripts are maintained in their native style.
`services/prompts.py` keeps its original bytes and CRLF line endings because frozen
evaluation manifests verify its SHA-256 hash.

## Verify changes

```powershell
npm run build
python -m pytest tests services evaluation -q
```

Tests use scripted AI providers and isolated state. Do not run live evaluation commands
as a substitute for regression tests: those commands can transmit evidence and consume
provider allowance.

For browser checks, use the isolated preview rather than real analyst state:

```powershell
python -m evaluation.serve_compact_ui --fixture --port=8813
```

This preview displays an offline-test banner and blocks external model calls. It is not a
hosted product demo. The normal Windows launcher remains `start.cmd`.

## Responsibilities

- Put reusable presentation controls in `src/components/` and data helpers in `src/lib/`.
- Keep provider credentials and evidence validation on the backend.
- Keep analyst decisions separate from AI proposals.
- Preserve existing saved reports and audit events during maintenance.
- Do not edit generated evidence files merely to make a test pass.
