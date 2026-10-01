# Score policy 1.1.0

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
skipped keep the strict score **unknown**. An `ok` stage with invalid scoring
metrics also makes it unknown. A quick profile exposes omitted stages; its score
applies only to its declared scope. Compare like profiles and tool versions.

## Provisional observed score

Incomplete scans also show an **observed score**. Only `ok` stages with validated
scoring metrics contribute. Take the lowest contributing stage score per category,
then weight the contributing categories once. A category with another incomplete
required stage is explicitly listed as partial. Missing or failed measurements
contribute neither a clean score nor a zero. No usable measurement means no score.

The receipt includes `assessment.observed`: its score/grade/categories,
`contributing_weight`, `applicable_weight`, `partial_categories`,
`contributing_stages`, and `excluded_stages`. Applicable weight includes categories
selected by that profile; it is not always 100. Stage coverage and weight coverage
are separate: a category can have some validated measurements while another
required stage in it is incomplete. Check both before comparing results.

Example: validated lint 75 (weight 15) and complexity 85 (weight 20), with types
unavailable (weight 20), give `(75×15 + 85×20)/35 = 80.71`. Measured category weight
is 35/55. That **provisional B** helps focus review; it does not approve a merge,
assert complete evidence, or replace the strict score used by CI. Known blockers
also cap observed scores at 20. A change in contributing scope is not evidence of
a code-quality improvement.

Positively identified binary assets are outside source/text analysis. The scope
manifest lists their paths, sizes, classification and reasons. Unknown, unreadable
or omitted possible source remains a required evidence gap. Binary analysis and
archive contents are not certified by this static text scan.

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
