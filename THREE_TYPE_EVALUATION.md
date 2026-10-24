# Current three-type detection check

The bundled queue was generated from the complete CIC-IDS2017 `GeneratedLabelledFlows.zip` Monday, Tuesday, Wednesday, and Friday PortScan files. The unit below is a source/destination/minute group, not a raw flow or Case. Dataset labels were used only after detection to score the rules; they were not used to select alerts or sent to the AI.

| Rule type | Correct matches | Benign false alerts | Missed labeled groups | Precision | Recall |
| --- | ---: | ---: | ---: | ---: | ---: |
| PortScan | 11 | 1 | 16 | 91.67% | 40.74% |
| DoS | 23 | 1 | 52 | 95.83% | 30.67% |
| Suspected brute-force | 122 | 0 | 5 | 100% | 96.06% |

Across these three labeled attack types, 156 groups were detected, 73 were missed, and 2 Benign groups triggered attack rules (68.12% recall, 98.73% precision among included groups). The separate Monday `NeedsReview` review heuristic selected one Benign-labeled group; it is an alert candidate rather than an attack prediction. Grouping the 159 alerts produces 10 Cases: 2 suspected brute-force, 3 DoS, 4 PortScan, and 1 NeedsReview. The benign rule matches remain in the queue so analysts can see genuine false positives instead of an all-attack showcase.

This is an **in-sample historical check**. The 50-connections/minute FTP/SSH cutoff was selected after examining this archive, so the 100% observed brute-force precision is not an independent estimate and should not be presented as a general guarantee. The flow records do not contain authentication outcomes, and repeated connections are only a suspicion of credential guessing. The AI receives rule output and sampled records, but no dataset labels. It may return `Likely Attack`, `Likely Benign`, or `Needs Review`; no result has been prefilled. Positive evidence of legitimate activity may be missing, so a normal-labeled Case can correctly remain `Needs Review`.

The earlier DDoS results in `DETECTION_AUDIT.md` belong to the archived configuration. `data/detection-evaluation.json` contains this run's full confusion table and rule settings. Independent traffic and a held-out threshold selection are needed before making deployment claims.
