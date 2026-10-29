# Risk scoring

ChainWatch gives every finding a risk score from 0 to 100, a risk level, and the factors that
produced the score. The rules live in `src/risk/scoring.ts`, the ordering in
`src/risk/ranking.ts`, and the pass or fail decision in `src/policy/evaluate.ts`.

The score answers one question: how urgent is this advisory for this project? It is not a
probability that the vulnerability is exploited, and it does not show that the vulnerable code
is reachable. Reachability is not evaluated (see the limitations below).

## Formula

```
risk = weights.severity * severity + weights.exposure * exposure
```

Both `severity` and `exposure` are on a 0 to 100 scale. The default weights are
`severity: 0.8` and `exposure: 0.2`. The configuration must set weights that are between 0
and 1 and sum to 1. The score is rounded to one decimal place.

Each factor is also reported with its contribution (`weight * value`, rounded), so the
score can be checked by hand.

## Severity

Severity comes from the advisory, in this order of preference:

1. **CVSS v3 vector.** The base score from the vector, multiplied by 10. A score of 7.5
   becomes 75. If an advisory has several vectors, the highest score is used.
2. **Label only.** An advisory with no vector but a label from OSV maps to a fixed value:

   | Label              | Value |
   | ------------------ | ----- |
   | CRITICAL           | 95    |
   | HIGH               | 80    |
   | MODERATE or MEDIUM | 55    |
   | LOW                | 20    |

3. **No usable data.** No score is assigned (see "Unknown" below).

## Exposure

Exposure describes how the package reaches the project. It is set from the lockfile flags:

| Dependency kind          | Value | Reason shown                |
| ------------------------ | ----- | --------------------------- |
| Development only (`dev`) | 40    | Development-only dependency |
| Optional (`optional`)    | 60    | Optional dependency         |
| Anything else            | 100   | Production dependency       |

A development dependency is checked, but it ships to users less often than a production
dependency, so it scores lower. The values are a judgement, not measured data.

## Levels

| Level    | Score                                          |
| -------- | ---------------------------------------------- |
| critical | 90 or more                                     |
| high     | 70 to below 90                                 |
| medium   | 40 to below 70                                 |
| low      | below 40                                       |
| unknown  | no score (the advisory has no usable severity) |

The thresholds are the first calibration and have not been tuned against a labelled corpus.
Changing them changes which findings fail the policy, so change them only with a reason
recorded in the plan or in `docs/decisions/`.

## Unknown is not zero

An advisory with no usable severity gets `riskScore: null` and level `unknown`. It never
gets a score of zero, because a missing score is not the same as a safe one. Unknown findings
are listed after every scored finding.

Policy handles them with `policy.unknownSeverity`:

- `report` (default): the finding is shown but does not fail the scan.
- `fail`: the finding fails the scan whatever `failOn` says.

## Ranking

Findings are sorted by risk score, highest first. Ties break on package name, then version
(numeric compare), then advisory ID. The order is the same on every run.

## Policy decision

The decision uses the risk level, not the raw score:

1. An exception in `policy.ignore` that matches the advisory ID or one of its aliases, and has
   an expiry date on or after the current UTC day, hides the finding. It is counted in
   `ignoredFindingIds`.
2. With `failOn: none` nothing else fails, and the report says the policy is not gating.
3. Otherwise a finding fails when its level is at least `failOn`. The order is
   low (1), medium (2), high (3), critical (4).
4. Unknown findings follow `unknownSeverity` as above.

`passed` is true when no finding fails. An expired exception stops hiding its findings and
the report prints a warning naming the advisory and its expiry date.

The scan exit code then follows the README: 1 for a failed policy, 3 for an incomplete scan
(which outranks 1), 0 otherwise.

## Worked example

A production dependency with a CVSS 7.5 advisory, under the default weights:

```
severity contribution = 0.8 * 75  = 60.0
exposure contribution = 0.2 * 100 = 20.0
risk = 80.0  -> high
```

The same advisory on a development-only dependency gives `0.8 * 75 + 0.2 * 40 = 68.0`, which
is medium. With the default `failOn: high`, the production case fails the policy and the
development case does not.

## Limitations

- Reachability is not evaluated. A high score does not mean the vulnerable function runs.
- Exposure has three values only. It does not look at how the project imports the package.
- The label values and level thresholds are initial choices and have not been calibrated
  against a labelled set of projects.
- Severity depends on the advisory data. OSV records can be incomplete or change over time.
  Reports show how many lookups came from the cache and how many were past their TTL, and the
  JSON result records the oldest cached fetch time (`advisoryData.oldestFetchedAt`).
