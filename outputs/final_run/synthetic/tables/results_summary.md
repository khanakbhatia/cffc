# Results summary

> **SYNTHETIC TEST DATA - NOT AWS EVIDENCE - NOT RESEARCH RESULTS**

Data provenance: **synthetic**

| run | scenario | config | mode | window_s | SC | CC | P | R | F1 | FCR | TOA | TC | TDR | time_s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| R01 | scenario_a | OR-matching | or | 300 | 94.1% | 100.0% | 60.0% | 100.0% | 75.0% | 40.0% | 100.0% | 100.0% | — | 0.05 |
| R02 | scenario_a | AND-matching | and | 300 | 94.1% | 100.0% | 33.3% | 33.3% | 33.3% | 66.7% | 66.7% | 100.0% | — | 0.03 |
| R03 | scenario_a | Baseline | baseline | N/A | 94.1% | 100.0% | undef | undef | undef | undef | 100.0% | 100.0% | — | 0.02 |
| R04 | scenario_a | OR, narrow | or | 60 | 94.1% | 100.0% | 75.0% | 100.0% | 85.7% | 25.0% | 100.0% | 100.0% | — | 0.02 |
| R05 | scenario_a | OR, wide | or | 900 | 94.1% | 100.0% | 42.9% | 100.0% | 60.0% | 57.1% | 100.0% | 100.0% | — | 0.02 |
| R06 | scenario_b | OR-matching | or | 300 | 95.0% | 100.0% | 60.0% | 100.0% | 75.0% | 40.0% | 100.0% | 100.0% | — | 0.02 |
| R07 | scenario_b | AND-matching | and | 300 | 95.0% | 100.0% | 100.0% | 100.0% | 100.0% | 0.0% | 100.0% | 100.0% | — | 0.02 |
| R08 | scenario_b | Baseline | baseline | N/A | 95.0% | 100.0% | undef | undef | undef | undef | 100.0% | 100.0% | — | 0.02 |
| R09 | scenario_b | OR, narrow | or | 60 | 95.0% | 100.0% | 100.0% | 100.0% | 100.0% | 0.0% | 100.0% | 100.0% | — | 0.02 |
| R10 | scenario_b | OR, wide | or | 900 | 95.0% | 100.0% | 60.0% | 100.0% | 75.0% | 40.0% | 100.0% | 100.0% | — | 0.02 |
| R11 | scenario_c | OR-matching | or | 300 | 94.0% | 100.0% | 100.0% | 100.0% | 100.0% | 0.0% | 100.0% | 100.0% | — | 0.02 |
| R12 | scenario_c | AND-matching | and | 300 | 94.0% | 100.0% | 100.0% | 40.0% | 57.1% | 0.0% | 100.0% | 100.0% | — | 0.02 |
| R13 | scenario_c | Baseline | baseline | N/A | 94.0% | 100.0% | undef | undef | undef | undef | 100.0% | 100.0% | — | 0.02 |
| R14 | scenario_c | OR, narrow | or | 60 | 94.0% | 100.0% | 100.0% | 100.0% | 100.0% | 0.0% | 100.0% | 100.0% | — | 0.02 |
| R15 | scenario_c | OR, wide | or | 900 | 94.0% | 100.0% | 100.0% | 100.0% | 100.0% | 0.0% | 100.0% | 100.0% | — | 0.02 |
| R16 | all | Tamper test | tamper | N/A | — | — | — | — | — | — | — | — | 100.0% | — |

`—` = not measured/not applicable for this run; `undef` = mathematically undefined (e.g., zero grouped pairs). Values are never estimated.
