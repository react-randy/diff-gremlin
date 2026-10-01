# Score policy 1.0.0

A score describes observed static signals. It cannot certify security, provenance,
correctness, maintainership, or whether a human wrote the code.

| Category | Weight | Clean control | Lower score |
| --- | ---: | --- | --- |
| Lint | 15 | 0 diagnostics | Counts: 1–5 → 90; 6–20 → 75; 21–50 → 60; 51–100 → 40; >100 → 0 |
| Types | 20 | 0 errors and warnings | Errors: 1–3 → 90; 4–10 → 75; 11–30 → 50; 31–100 → 25; >100 → 0. Warnings use lint bands; take the lower score. |
| Complexity | 20 | Maximum function CC ≤10 | ≤20 → 85; ≤30 → 70; ≤40 → 50; ≤50 → 30; >50 → 0 |
| Duplication | 15 | ≤5% | ≤10% → 90; ≤20% → 75; ≤40% → 55; ≤60% → 30; >60% → 0 |
| Security | 20 | No actionable findings | Start at 100; each low costs 2, medium 8, high 25, critical 100; floor 0. Informational observations cost 0. |
| Hygiene | 10 | License, README, observed tests, gitignore | 25 points per observed item. CI/lock facts are informational. |

For multiple analyzers in a category, take the lowest score. Each category appears
once in the weighted mean. Inapplicable categories are absent; report that scope.
Health, maintainability, history and parser structure remain visible informational
evidence and do not add duplicate weight.

Required stages that are missing, failed, timed out, limited, unsupported or
skipped make the headline score **unknown**. An `ok` stage with invalid scoring
metrics also makes it unknown. A quick profile exposes omitted stages; its score
applies only to its declared scope. Compare like profiles and tool versions.

Known critical findings, CC >50, duplication >60%, or no observed license file
produce **hold**. If a complete numeric score exists, cap it at 20 (F). Missing
evidence never erases a known blocker. Grades: A ≥90, B ≥80, C ≥70, D ≥60, F <60.

Decisions: `hold` for known blockers; `unknown` for incomplete required evidence;
`review` for medium/high findings; `no_configured_blockers` otherwise. The last
decision means the configured static checks found no blocker. Review the actual
findings, dependencies, tests and project ownership before adoption or merge.

CLI exits: 0 complete with no configured gate failure; 1 known blocker or failed
`--fail-under`/`--fail-on` gate; 2 usage/acquisition/operational error; 3 incomplete
evidence. `--require-complete` states CI intent explicitly; incomplete checks
already exit 3 by default. Thresholds cannot turn unknown into a passing number.

Calibration is tested against independent clean, deliberately bad, mixed-language
and missing-tool fixtures before evaluating Diff Gremlin itself. Changing this
policy requires a version change and new published calibration evidence.
