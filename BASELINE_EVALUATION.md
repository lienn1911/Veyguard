# Offline detection baseline (CIC-IDS2017)

The complete `GeneratedLabelledFlows.zip` was evaluated on 2026-10-22. These are historical dataset results at the source-IP/destination-IP/minute-group level, not live SOC performance. The baseline remains an offline experiment; the application still uses its existing rules.

## Protocol

- Monday's 529,918 Benign flow rows became 123,025 groups. Distinct minutes were divided chronologically into 60% training, 20% calibration and 20% holdout blocks, with five minutes omitted at each boundary. Up to 50,000 normal training groups were sampled with seed 2017.
- Isolation Forest used 100 trees and eight traffic features: log flow, packet and byte counts; log unique destination and source ports; their port entropies; and log distinct sources to the destination in the minute. Labels, filenames, IP values and absolute timestamps were not model features.
- Score cutoffs were selected only from 30,994 separate Monday calibration groups at target group false-positive rates of 0.01%, 0.1% and 1%. Monday's 24,557 later groups were held out. Wednesday and two Friday files were used as shifted-day tests; labels were read only to calculate metrics.
- Groups containing mixed Benign/attack labels or unsupported attack types were excluded from the benign-versus-known-attack metrics. Consecutive flagged benign groups for the same source/destination within five minutes were counted as candidate false-positive Cases; this is a count, not a Case false-positive rate.

| Target group FPR | Monday holdout benign FP | Shifted-day benign FP | Known attack groups detected | Candidate benign Cases |
| --- | ---: | ---: | ---: | ---: |
| 0.01% | 2 / 24,557 | 67 / 146,700 | 11 / 123 | 23 |
| 0.1% | 7 / 24,557 | 147 / 146,700 | 54 / 123 | 75 |
| 1% | 255 / 24,557 | 1,014 / 146,700 | 91 / 123 | 550 |

At the 0.1% target, shifted-day Benign group false-positive rates varied: Wednesday 100/101,395 (0.099%), Friday DDoS file 31/14,719 (0.211%), and Friday PortScan file 16/30,586 (0.052%). A calibration target is therefore not a guarantee on another day.

The existing rule detector found 54/123 known-attack groups and produced zero Benign-group alerts on those same three comparison files. It labeled 20 DDoS groups as DoS, so its exact DDoS-type recall was 0/21 despite detecting traffic in 20/21 groups. The anomaly baseline found 54/123 groups at the 0.1% target but does not classify attack type and produced 147 Benign-group alerts. These results do not justify replacing the rules. Anomaly means deviation from Monday traffic, not a verified attack; a separate analyst/AI review would still be required.

The baseline features, model size and cutoff procedure were fixed before inspecting the resulting scores. The CIC dataset's labels and time patterns remain possible sources of evaluation bias. A different network would need new normal training and calibration data. The reported candidate Case counts have no denominator of all possible benign Cases, and no human-reviewed Case-level false-positive rate is claimed.

Reproduce with `python -m services.evaluate_detection PATH_TO_ZIP -o data/detection-evaluation.json`, `python -m services.evaluate_baseline PATH_TO_ZIP -o data/baseline-evaluation.json`, then `python -m services.evaluate_system --detector-report data/detection-evaluation.json --baseline-report data/baseline-evaluation.json` after installing `requirements-eval.txt`.


## Scope revision — 2026-10-23

The competition scope is now PortScan, DoS and BruteForce. Earlier DDoS comparisons in this document are archived experimental results. The baseline evaluator now compares Tuesday, Wednesday and Friday PortScan with Monday normal-only training/calibration/test blocks; SSH/FTP labels map to BruteForce, while DDoS is excluded from the three-type denominator. Benign is scoring truth only. A high anomaly score is not an attack verdict and a low score is not a safety conclusion. No revised Isolation Forest fit has been claimed in this change. Follow EVALUATION_PROTOCOL.md for external holdout requirements; chronological blocks from an archive already used for development do not validate the deployed rules independently.
