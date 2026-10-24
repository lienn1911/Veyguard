# Review priority

This field orders investigation work. It is not a calibrated security risk,
severity rating, attack probability or a safe-to-close decision. The activity
heuristic has not been validated against analyst urgency labels.

`services/review_priority.py` is the single source used by both Home and the
case list. Version `activity-v1` awards points as follows; only the highest tier
within a measurement applies.

| Measurement | Points |
| --- | ---: |
| Window-average flow records per minute at least 5,000 / 10,000 | 1 / 2 |
| Related alert count at least 3 / 10 | 1 / 2 |
| At least three distinct observed alert source IPs | 2 |
| Maximum per-alert destination ports at least 100 / 250 | 1 / 2 |

High is at least 5 points, Medium is 3–4, and Low is 0–2. Minute-start windows
include the final minute; gaps count toward elapsed time. Missing alerts,
invalid times or incomplete/inconsistent measurements produce Not assessed,
never a synthetic zero/Low. Not assessed sorts alongside High so unknown cases
are not quietly pushed below Low. Date breaks equal-level ties.

Ground-truth labels, AI verdicts, confidence and provider failure states are
not inputs. AI findings remain visible in case details for analyst context;
there is no AI-generated priority or automatic AI downgrade. The existing
guardrail prohibition on AI priority changes remains in place. Asset importance,
service impact and failed authentication are not inferred from flow counts.

An authenticated analyst can set High, Medium or Low, or restore the rule
suggestion. Every change requires a 10–1,000 character reason and explicit
confirmation. The HTTP route binds the analyst to the signed-in session and
uses the existing CSRF protection. Each change appends a
`CASE_REVIEW_PRIORITY_SET` event containing prior level/source, chosen override,
rule suggestion, policy version and reason. No historical event is rewritten.
Home and the list read the latest event; a new case record snapshots the field.
Old saved records are not retroactively updated.

This prototype policy is a starting point for review-order evaluation. It does
not establish that activity volume reflects business impact, and must not be
used to justify auto-closure or claim validated risk scoring.

Verification: `python -m pytest services/test_review_priority.py` covers grades,
inclusive windows, missing values, AI/label independence, identity binding,
manual override/reset and append-only event persistence.
