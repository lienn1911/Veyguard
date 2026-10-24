# Three-type detection and grouping evaluation — 2026-10-23

Competition attack scope: **PortScan, DoS, BruteForce**. Benign is dataset ground truth for offline scoring, not an attack rule or an automatic safety conclusion. No alert means the configured rules did not fire. `NeedsReview` is an optional review candidate outside these three attack rules.

## Full historical development check

The complete CIC-IDS2017 GeneratedLabelledFlows Monday, Tuesday, Wednesday and Friday PortScan CSVs were rescanned, including groups that never generated an alert. This is a historical development result: these data were already inspected when choosing thresholds. It is not an independent test or a live-network accuracy claim.

| Rule | TP | FP from Benign | FN | Precision | Recall |
| --- | ---: | ---: | ---: | ---: | ---: |
| PortScan | 11 | 1 | 16 | 91.67% | 40.74% |
| DoS | 23 | 1 | 52 | 95.83% | 30.67% |
| BruteForce (suspected) | 122 | 0 | 5 | 100.00% | 96.06% |

Unit: source-file/source-IP/destination-IP/calendar-minute group, not a flow or case. Of 356,103 groups, 11 Other attack groups were excluded; there were no Mixed or DDoS groups in these selected files. In-scope attacks total 229 groups; 156 were detected and 73 missed. No cross-type predictions occurred in this run. There were 355,863 pure Benign groups: 2 triggered rules and 355,861 did not. Binary attack precision was 156/158 = 98.73%, recall 156/229 = 68.12%, and Benign false-positive rate 2/355,863 = approximately **0.000562%**, not zero. The low false-positive rate does not compensate for the missed attacks.

The committed `evaluation/detection-development-20261023.json` contains input/code hashes, the full confusion matrix, exclusions and 75 error rows (2 FP, 73 FN). Archive SHA-256: `7bdbef286f8893f31c6db12105fa097fa5c2dcc6733179037a08129d150ea27a`. The earlier `data/detection-evaluation.json`, bundled preview and DDoS audit are older configurations, not the revised grouping report.

## Grouping corrections and results

Cases now require the same source file, rule type and ordered source/destination pair, plus target login port for BruteForce. Consecutive minute starts separated by at most five minutes join; longer gaps split. The full grouping key and starting minute enter the incident ID, preventing collisions between different rules or FTP/SSH targets. Alert timestamps represent the bucket start rather than the time of a sampled record; evidence records retain original times. The latest evidence sample is selected by timestamp even when CSV rows are unordered. Preview selection no longer consults the DDoS ground-truth marker.

With review candidates disabled, the full export contains **158 alerts and 9 cases**: 4 PortScan, 3 DoS and 2 BruteForce. Offline case scoring identifies 2 pure Benign alert cases and 0 mixed-label cases. Those two false-positive cases are retained, not filtered out using truth. Related-case links do not merge cases or evidence. A mixed-label case remains possible because a pair can have both benign and attack traffic; production grouping must not use scoring labels to hide it.

`evaluation/grouping-development-20261023.json` records each case and scoring truth. Case scoring only sees alert-bearing cases, so these counts cannot estimate case-level recall or a benign case false-positive rate. The previously documented 10-case export included one optional Monday NeedsReview candidate; it is a different configuration.

## Reproduce

```
python -m services.evaluate_detection path/to/GeneratedLabelledFlows.zip -o evaluation/detection-development-20261023.json
python -m services.alerts path/to/GeneratedLabelledFlows.zip -o data/alerts-evaluation-20261023.json
python -m services.evaluate_grouping data/alerts-evaluation-20261023.json -o evaluation/grouping-development-20261023.json
python -m unittest services.test_detection_evaluation services.test_evaluate_baseline
```

The 19 focused tests cover detector label independence, per-port BruteForce thresholds, ambiguous archive rejection, case ID collisions, pair isolation, gap boundaries, mixed-label case reporting, full-export enforcement, baseline scope, FP/FN/TN accounting and holdout overlap/tamper checks. Synthetic fixtures demonstrate software behavior, not independent performance.

## Independent evaluation and remaining limits

`services.evaluate_detection --holdout-manifest` accepts an explicit external CSV selection and rejects input/code hashes that differ from a frozen manifest or overlap declared development hashes. See `EVALUATION_PROTOCOL.md` for fields and freezing requirements. The separate CIDDS-001 external-domain holdout has now been completed and reproduced; see [evaluation/CIDDS_HOLDOUT.md](evaluation/CIDDS_HOLDOUT.md) and [JOINT_ACCEPTANCE.md](JOINT_ACCEPTANCE.md). Its poor recall must be reported separately from development scores. Repackaging or splitting the already inspected archive does not make it independent.

Thresholds were not retuned in this revision. PortScan and DoS have substantial false negatives. First-match rule priority can mask simultaneous behaviors. Fixed minute buckets miss slow activity and can split bursts. Repeated FTP/SSH flow connections do not prove failed logins; high flow/packet volume does not prove service outage. Dataset timestamps have no timezone metadata: existing ISO values should be treated as dataset clock values, not independently verified UTC. Labels may be imperfect, sampled evidence is biased, and this result does not establish production SOC accuracy.

The revised grouping changes case IDs. The UI alert, timeline and raw-context bundle now uses the nine-case export and passed reconstruction checks. Old decisions and audit events remain under their original IDs and were not transferred. The standalone historical Isolation Forest baseline now shares the three-type scope, but was not refit as part of this change. Its old DDoS scores must not be presented as current three-type results.
