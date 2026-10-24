# External detection holdout: CIDDS-001

This is an **external-domain test**, not a CIC-IDS2017 development score. The
CIDDS-001 OpenStack internal weeks 1–4 archive was not used to choose the
detector's thresholds. The source archive, detector, and adapter hashes were
frozen in `cidds_holdout_manifest.json` before scores were inspected. The
manifest records a performance-only switch from Python row partitioning to
DuckDB aggregation before any scores were produced.

Source: [CIDDS-001, Coburg University](https://www.hs-coburg.de/forschen/cidds-coburg-intrusion-detection-data-sets/).

## Fixed scoring unit

One CSV row counts as one flow record. A group is one source IP, destination IP,
calendar minute, and source file. Packet counts use the `Packets` column.
`class=normal` is Benign truth; `attackType=portScan/dos/bruteForce` maps to the
three attack truths. A group with out-of-scope or multiple attack labels is
excluded. A group mixing Benign and one target attack is scored as attack and
counted separately. The rule receives only counts, ports, and packets; labels
are used after prediction. Source and destination addresses are ordered, so
reverse-direction records form separate groups.

## Results

5,942,316 groups were scored across four internal weeks; 4,260 ambiguous or
out-of-scope groups were excluded. Of the scored groups, 786 mixed Benign with
one target attack. Values below are **minute-group** counts, not individual
flow counts or incident-level accuracy.

| Rule | True positives | False positives | False negatives | Precision | Recall |
| --- | ---: | ---: | ---: | ---: | ---: |
| PortScan | 48 | 0 | 40,617 | 100% | 0.12% |
| DoS | 56 | 0 | 80 | 100% | 41.18% |
| BruteForce | 2 | 0 | 555 | 100% | 0.36% |

The zero observed false positives occur with very few positive predictions;
they do not establish robust precision. The current CIC-derived thresholds
generalize poorly to this NetFlow source, especially PortScan and BruteForce.
CIDDS-001 uses unidirectional NetFlow records and different traffic and attack
patterns from CIC-IDS2017; this is a deliberate domain shift. Do not combine
these metrics with the CIC development metrics or tune the frozen test and
call the result independent. The full confusion matrix and hashes are in
`cidds_holdout_results.json`.
