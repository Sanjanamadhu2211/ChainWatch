# ChainWatch

ChainWatch is a local-first dependency risk analyzer for npm projects. It reads
`package-lock.json`, finds known vulnerabilities through the OSV database, shows the
dependency path that brings each one in, and ranks the results with an explainable risk
score. A policy in `chainwatch.yaml` decides when a scan fails, so the same tool works
locally and in CI.

It does not install packages, run install scripts, or execute project code.

## Requirements

- Node.js 22 or newer (the repository pins 24 in `.nvmrc`).
- An npm project with a `package-lock.json` (lockfile version 2 or 3).

## Install and build

ChainWatch is not published to npm yet. Build it from a clone:

```sh
git clone <this repository> chainwatch
cd chainwatch
npm ci
npm run build
node dist/index.js --help
```

## Usage

```sh
node dist/index.js scan path/to/project            # terminal report
node dist/index.js scan . --format json --output scan.json
node dist/index.js scan . --format html --output report.html
node dist/index.js scan . --fail-on critical       # override the policy level
node dist/index.js scan . --offline                # cached advisory data only
node dist/index.js report --input scan.json --format html --output report.html
node dist/index.js explain minimist@0.0.8 --input scan.json
```

| Command                    | What it does                                                                             |
| -------------------------- | ---------------------------------------------------------------------------------------- |
| `scan [path]`              | Looks up advisories for the lockfile, prints or writes a report, and applies the policy. |
| `report --input scan.json` | Renders a saved scan. It makes no advisory lookups and does not apply the policy.        |
| `explain <package> [path]` | Explains the findings for one package, live or from `--input scan.json`.                 |

Output formats are `terminal` (default), `json` and `html`. The JSON format follows
`docs/schema/scan-result.schema.json`, which is generated from the code.

### Exit codes

| Code | Meaning                                                                                   |
| ---- | ----------------------------------------------------------------------------------------- |
| 0    | The scan completed and the policy passed.                                                 |
| 1    | The scan completed and at least one finding fails the policy.                             |
| 2    | Bad arguments, an invalid configuration, or an unreadable input file.                     |
| 3    | The scan was partial or failed (for example OSV was unreachable). Code 3 outranks code 1. |

A result with code 3 is never a clean result, even when no findings were listed. The
report says so in every format.

## Configuration

Put a `chainwatch.yaml` next to the lockfile, or pass `--config`. The file is strict: an
unknown key is an error. See `chainwatch.example.yaml` for every option.

```yaml
version: 1
policy:
  failOn: high # critical | high | medium | low | none
  unknownSeverity: report
  ignore:
    - advisoryId: GHSA-xxxx-yyyy-zzzz
      reason: "Tracked upstream; temporary exception"
      expires: "2026-12-31"
```

An exception is active through its expiry day. After that the finding counts again and
the report prints a warning.

## Continuous integration

`.github/workflows/ci.yml` runs `npm run check` and `npm run build` on every pull
request and on every push to `main`, so a branch with an open pull request is checked once per
push. A second job scans the repository's own lockfile and
uploads the JSON report as the `chainwatch-scan` artifact.

## Privacy

Advisory lookups send package names and versions to the OSV API (`api.osv.dev`). Nothing
else leaves the machine. Use `--offline` to scan from the local cache without any
network request. Details are in `docs/threat-model.md`.

## Development

```sh
npm run check    # typecheck and lint
npm run build    # bundles dist/index.js with tsup
npm run format   # prettier --write
```

## Documentation

- `docs/architecture.md`: modules, their boundaries, and the scan flow.
- `docs/risk-scoring.md`: how the risk score, level and policy decision are computed.
- `docs/threat-model.md`: what ChainWatch trusts, what it does not, and its limitations.
- `docs/schema/scan-result.schema.json`: the JSON report schema.

## License

MIT. See `LICENSE`.
