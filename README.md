# SOC Triage

## Run

Install Node.js and pnpm, then run these commands from the repository root. On Windows, `start.cmd` also works after dependencies are installed.

```powershell
pnpm install
pnpm dev
```

## Source structure

```text
src/
  App.jsx              Navigation and page selection
  main.jsx             React entry
  styles.css           Active app styles
  components/
    AlertReview.jsx     Alert list and detail tabs
    Dashboard.jsx       Overview cards and empty states
    Icon.jsx            Shared SVG icons
    Sidebar.jsx         Desktop and mobile navigation
  modules/              Five empty UI files
services/               Five empty Python files
```

Each feature owner has one empty UI file and one empty Python file:

| Feature | UI | Python |
|---|---|---|
| Alert generation | `src/modules/alerts.jsx` | `services/alerts.py` |
| Incident triage | `src/modules/triage.jsx` | `services/triage.py` |
| Timeline | `src/modules/timeline.jsx` | `services/timeline.py` |
| Recommendations | `src/modules/recommendations.jsx` | `services/recommendations.py` |
| Safety guardrails | `src/modules/guardrails.jsx` | `services/guardrails.py` |

The empty files are not imported yet. Connect them when their owners finish implementation. `node_modules` and `dist` are generated and ignored by Git.
