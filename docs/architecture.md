# Architecture

ChainWatch is one TypeScript package that builds into one CLI bundle (`dist/index.js`). The code
is split into modules by responsibility. Each module may import only from the modules below it,
and ESLint enforces this with `no-restricted-imports` in `eslint.config.js`.

## Modules

| Module           | Responsibility                                                                | Must not import                            |
| ---------------- | ----------------------------------------------------------------------------- | ------------------------------------------ |
| `src/lockfile`   | Reads `package-lock.json` (versions 2 and 3) and builds the dependency graph. | cli, reports, advisories, risk, policy     |
| `src/advisories` | OSV client, advisory schema, CVSS base scores, version matching, file cache.  | cli, reports, lockfile, risk, policy       |
| `src/risk`       | Scores one finding and ranks findings. Pure functions.                        | cli, reports, lockfile, advisories, policy |
| `src/policy`     | Loads and validates `chainwatch.yaml`, then decides pass or fail.             | cli, reports, lockfile, advisories, risk   |
| `src/core`       | Orchestrates a scan: project loading, findings, and the scan result.          | cli, reports                               |
| `src/reports`    | Renders a scan result as terminal, JSON, or HTML. Validates saved scans.      | cli, lockfile, advisories, risk, policy    |
| `src/cli`        | Commander program, command handlers, and exit codes.                          | (top layer)                                |

`src/core` may use `lockfile`, `advisories`, `risk`, and `policy`. `src/reports` gets its
input as plain data, so it never needs to know how a scan was made. `src/cli` is the only
module that reads environment variables, writes to stdout, or chooses the exit code.

## Files that matter most

- `src/cli/index.ts`: the bundle entry point (tsup builds `dist/index.js`).
- `src/cli/cli.ts`: `buildProgram`, the commands and options.
- `src/cli/commands/scan.ts`: `runProjectScan`, `exitCodeFor`, the scan command.
- `src/core/project.ts`: `loadProject` finds the lockfile and loads the configuration.
- `src/core/scan.ts`: `runScan`, which runs the whole pipeline.
- `src/core/findings.ts`: `buildFindings`, which joins advisories to dependency paths.
- `src/risk/scoring.ts`: `scoreFinding` (see `docs/risk-scoring.md`).
- `src/policy/evaluate.ts`: `evaluatePolicy`.
- `src/reports/render.ts`: `renderReport` dispatches to the three formats.
- `src/reports/schema.ts`: `scanResultSchema`, the strict schema for saved scans.

## Scan flow

`chainwatch scan <path>` runs these steps in order:

1. **Load the project.** `loadProject` resolves the path, loads `chainwatch.yaml` (strict
   schema, exit 2 if invalid), and finds the first configured lockfile that exists.
2. **Read the lockfile.** `readNpmLockfile` checks the file size (`MAX_LOCKFILE_BYTES`) and the
   `lockfileVersion`, then `indexGraph` builds the dependency graph. Each node records its
   source (registry, workspace, or non-registry), whether it is dev-only or optional, and its
   path from the root.
3. **Look up advisories.** Only registry packages are looked up, one lookup per name and
   version. For each package:
   - a fresh cache entry is used if one exists (`AdvisoryCache`, TTL from config);
   - otherwise the package goes to `OsvClient.queryBatch` (`POST /v1/querybatch`, up to 1000
     per request, with retries and a 15 second timeout), and each advisory ID not already cached
     is fetched with `GET /v1/vulns/{id}`;
   - in offline mode, cache entries are used even when past their TTL, and missing ones are
     recorded as failures.
     Responses are validated with Zod. A failed lookup is recorded against the package, not
     dropped silently.
4. **Build findings.** `buildFindings` matches each advisory's affected ranges against each
   installed version (`matching.ts`), attaches the dependency paths, and computes the fixed
   version. `scoreFinding` gives each finding its score, level, and factors, and `rankFindings`
   sorts them.
5. **Apply the policy.** `evaluatePolicy` applies the exceptions in `policy.ignore`, the `failOn`
   level (the CLI `--fail-on` overrides the config), and `unknownSeverity`. It returns the
   policy decision and the warnings for expired exceptions.
6. **Save the cache.** Successful live lookups are written to the cache file. A write failure
   becomes a warning and does not change the result.
7. **Assemble the result.** `runScan` returns a `ScanResult` with `status`
   (`complete`, `partial`, or `failed`), coverage counts, advisory data freshness, the
   findings, the policy decision, and warnings. The result is plain data.
8. **Render and exit.** `renderReport` produces the terminal, JSON, or HTML output, which is
   written to stdout or `--output`. `exitCodeFor` maps the result to an exit code.

`chainwatch report --input` starts at step 8 with a saved `ScanResult`, validated by
`scanResultSchema`. It makes no lookups and does not re-run the policy. `chainwatch explain`
uses steps 1 to 4 for a single package, or reads a saved result with `--input`.

## Exit codes

`exitCodeFor` in `src/cli/commands/scan.ts`:

- status not `complete` gives 3, whatever the findings;
- otherwise a failed policy gives 1;
- otherwise 0.

Exit 2 is raised earlier, for bad arguments, invalid configuration, or an unreadable or invalid
input file. Errors that have a code (`ChainwatchError` subclasses such as `ConfigError` and
`LockfileError`) print a message to stderr and exit 2.

## Output contracts

- The JSON result is `schemaVersion: "1.0"`. The schema at `docs/schema/scan-result.schema.json`
  is generated from `scanResultSchema`. A test fails if the committed file is out of date, and
  `UPDATE_SCHEMA=1 npx vitest run tests/unit/scan-result-schema.test.ts` regenerates it.
- The HTML report is one file with no scripts. Its security rules are in `docs/threat-model.md`.

## Testing layout

- `tests/unit`: per-module tests (scoring, matching, policy, cache, renderers, schema).
- `tests/e2e`: builds the CLI and runs it against a fake OSV server (`tests/e2e/helpers.ts`)
  that replays recorded responses from `tests/fixtures/osv`. No network access is needed.
- `npm run check` runs typecheck, lint, and the full suite, including the end-to-end tests.
  CI runs it on every push to `dev` and `main`.
