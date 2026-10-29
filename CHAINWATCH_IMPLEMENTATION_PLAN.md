# Chainwatch — Architecture & Sequential Implementation Plan

## 1. Overview

**Chainwatch** is a TypeScript-first, local-first dependency security CLI. It analyzes software dependencies, identifies known vulnerabilities, traces how vulnerable transitive dependencies enter a project, prioritizes findings using transparent risk rules, and recommends remediation.

**Product principle:** one analysis engine, multiple interfaces. The CLI, JSON/HTML/SARIF reports, and CI integration must all consume the same engine rather than implementing separate security logic.

### Target outcome

Build a credible, usable dependency risk analyzer in six phases (a usable local scanner after Phase 4), focusing on explainability and remediation prioritization rather than trying to replace existing tools such as OSV-Scanner, Snyk, or Dependabot.

### v1 scope

- Scan npm projects using `package-lock.json` (`lockfileVersion` 2 or 3; v1 is rejected with a clear error).
- Resolve direct and transitive dependency relationships from the lockfile, including workspaces.
- Query the OSV API for known vulnerabilities.
- Explain the dependency path to each vulnerable package.
- Rank findings using deterministic, documented risk rules.
- Recommend fixed versions when reliable advisory metadata exists.
- Generate terminal, JSON, and HTML reports (SARIF as a stretch goal, see Phase 5).
- Integrate with CI using configurable security thresholds.

### Out of scope for v1

- Proving runtime exploitability or code reachability.
- Detecting every malicious package or zero-day vulnerability.
- Executing package installation scripts.
- Automatically upgrading dependencies or creating pull requests.
- Computing semver-compatible upgrade paths through parent dependencies (v1 suggests an action, it does not solve resolution).
- Non-registry packages (git, tarball, file). They are reported as **skipped**, never as clean.
- `chainwatch config init` (ship `chainwatch.example.yaml` instead; add the command later).
- Requiring a backend, hosted dashboard, or LLM.

These exclusions keep the project achievable and make its security claims defensible.

---

## 2. Architecture

```text
Repository (manifests + lockfiles)
              |
              v
      CLI entry point
 (arguments, config, exit codes)
              |
              v
       Scan orchestrator
              |
       +------+------+
       |             |
       v             v
 Lockfile parser   OSV client (+ cache)
       |             |
       v             v
 Package inventory + advisory data
       |             |
       v             v
    Dependency graph and finding assembly
                    |
                    v
               Analysis engine
      (deduplication, graph paths, risk scoring)
                    |
                    v
           Normalized scan result
                    |
          +---------+---------+
          |         |         |
          v         v         v
       Terminal  JSON/HTML   CI policy
                             |
                             v
                      Exit code / artifact
```

### Scan flow

1. Discover the repository and validate the lockfile (size limit, schema, supported `lockfileVersion`).
2. Parse installed packages into a normalized inventory; mark non-registry packages as skipped.
3. Build a dependency graph from actual lockfile relationships.
4. Query OSV `querybatch` for name+version pairs (chunked to the API limit, following `next_page_token`). The response contains only vulnerability IDs.
5. Fetch each distinct vulnerability record by ID (`/v1/vulns/{id}`) and normalize it. Cache by vulnerability ID.
6. Confirm the affected status. When online, trust OSV's own match for the queried version. Local range matching is used only for offline cache hits and as a sanity check.
7. Drop withdrawn advisories, then aggregate findings by package version and canonical advisory (alias-merged) while retaining dependency paths.
8. Calculate explainable risk scores.
9. Evaluate CI policy separately from scoring.
10. Render reports and return an appropriate exit code.

**Reliability rule:** network failures must be distinguishable from a clean scan. A failed vulnerability lookup must never silently produce a successful zero-finding result.

### Architectural boundaries

- Parsing, advisory retrieval, analysis, policy evaluation, and reporting are separate **directories within one package**, not separate workspace packages. Split into workspace packages later only if a real consumer needs one (for example a reusable `core` library).
- Keep dependencies one-way: `cli` → `core` → (`lockfile`, `advisories`, `risk`, `policy`); `reports` consumes only `ScanResult`. Enforce with ESLint `no-restricted-imports` rules so boundaries are checked, not just documented.
- Analysis modules are independently testable and do not own CLI presentation logic.
- Avoid circular dependencies. Shared domain types live in `src/core/types.ts`.

---

## 3. Repository structure

```text
chainwatch/
├── src/
│   ├── cli/
│   │   ├── commands/
│   │   │   ├── scan.ts
│   │   │   ├── explain.ts
│   │   │   └── report.ts
│   │   ├── cli.ts
│   │   └── index.ts
│   ├── core/
│   │   ├── scan.ts
│   │   ├── types.ts
│   │   └── errors.ts
│   ├── lockfile/
│   │   ├── npm.ts
│   │   └── graph.ts
│   ├── advisories/
│   │   ├── osv-client.ts
│   │   ├── schema.ts          # Zod schemas for OSV responses
│   │   ├── matching.ts
│   │   ├── cvss.ts            # vector/label -> score
│   │   └── cache.ts
│   ├── risk/
│   │   ├── scoring.ts
│   │   ├── ranking.ts
│   │   └── explain.ts
│   ├── policy/
│   │   ├── evaluate.ts
│   │   └── config.ts
│   └── reports/
│       ├── terminal.ts
│       ├── json.ts
│       ├── html.ts
│       └── sarif.ts           # stretch
│
├── tests/
│   ├── fixtures/
│   │   ├── vulnerable/
│   │   ├── patched/
│   │   └── malformed/
│   ├── unit/
│   ├── integration/
│   └── e2e/
│
├── .github/workflows/ci.yml
├── docs/
│   ├── architecture.md
│   ├── threat-model.md
│   ├── risk-scoring.md
│   └── decisions/
├── package.json
├── package-lock.json
├── tsconfig.json
├── vitest.config.ts
├── eslint.config.js
├── .prettierrc.json
├── .nvmrc
├── chainwatch.example.yaml
├── README.md
├── CONTRIBUTING.md
└── LICENSE
```

### Module responsibilities

| Module | Responsibility | Must not do |
|---|---|---|
| `core` | Orchestrate scans and expose the engine API | Parse CLI arguments or render reports |
| `lockfile` | Parse lockfiles, normalize packages, construct graphs | Make network requests |
| `advisories` | Retrieve, cache, normalize, and match vulnerability data | Decide which findings block CI |
| `risk` | Calculate scores and explain contributing factors | Perform I/O or mutate packages |
| `policy` | Apply thresholds, allowlists, and failure rules | Change vulnerability scores |
| `reports` | Render a `ScanResult` | Recalculate risk or query OSV |
| `cli` | Parse commands, configure execution, map outcomes to exit codes | Duplicate security logic |

### Tooling defaults (decide once, in the first session)

- Node.js: current Active LTS, pinned in `.nvmrc`, `engines`, and CI.
- ESM (`"type": "module"`), TypeScript strict mode.
- CLI parsing: `commander`. Build: `tsup`. Tests: Vitest. Validation: Zod. Version ranges: `semver`.
- JSON Schema for the report is **generated from the Zod schema** (not hand-written) and published in `docs/`.

---

## 4. Core data models

Use strict TypeScript, validate external data with Zod, and use ISO timestamps in serialized reports. These are initial internal contracts and can evolve as the implementation reveals real needs.

### Package and graph

```ts
export type Ecosystem = "npm";

export interface PackageId {
  ecosystem: Ecosystem;
  name: string;
  version: string;
}

export interface DependencyNode {
  /** Lockfile path key, e.g. "node_modules/a/node_modules/b". Unique per installed copy. */
  id: string;
  package: PackageId;
  direct: boolean;     // declared by the root project (or a workspace)
  dev: boolean;        // reachable only through devDependencies
  optional: boolean;
  peer: boolean;
  source: "registry" | "non-registry"; // non-registry nodes are skipped from lookup
}

export interface DependencyEdge {
  from: string;
  to: string;
  range: string;       // declared semver range, kept for remediation hints
  type: "prod" | "dev" | "optional" | "peer";
}

export interface DependencyGraph {
  nodes: DependencyNode[];
  edges: DependencyEdge[];
}
```

Rules for building the graph from `package-lock.json` (`packages` map):

- Node ID is the lockfile path key, because the same package can be installed at several versions and locations.
- Resolve each declared dependency using Node's lookup order: `<node>/node_modules/<name>`, then each ancestor's `node_modules`, then root `node_modules`.
- Handle `link: true` entries (workspaces), `npm:` aliases (use the entry's real `name`), `inBundle`, and the `dev` / `optional` / `devOptional` / `peer` flags.
- Entries whose `resolved` is not the npm registry (git, tarball, `file:`) get `source: "non-registry"`, are excluded from OSV queries, and are counted in `coverage.skipped`.
- Reconstructing the graph from `package.json` alone loses installed-version information, so do not do it.

### Normalized advisory

```ts
export interface AffectedRange {
  type: "SEMVER" | "ECOSYSTEM" | "GIT";
  events: {
    introduced?: string;
    fixed?: string;
    last_affected?: string;
    limit?: string;
  }[];
}

export interface Advisory {
  id: string;                 // as returned by OSV
  aliases: string[];
  summary?: string;
  withdrawn?: string;         // present => drop the advisory
  severity: {
    cvssVectors: { type: string; vector: string }[]; // e.g. CVSS_V3 / CVSS_V4
    label?: string;           // e.g. database_specific.severity: LOW|MODERATE|HIGH|CRITICAL
  };
  affected: {
    packageName: string;
    versions: string[];       // explicit affected versions, if listed
    ranges: AffectedRange[];  // structured, not flattened to strings
  }[];
  references: string[];
  modifiedAt?: string;
}
```

This is an internal normalized model, not a claim that every OSV record includes every field. The provider adapter validates upstream responses and tolerates missing optional fields. **Fixed versions are derived only from the `affected` entry for the queried package**, never from all entries in the record.

### Finding and risk explanation

```ts
export type RiskLevel = "critical" | "high" | "medium" | "low" | "unknown";

export interface RiskFactor {
  name: string;
  contribution: number;
  reason: string;
}

export interface Finding {
  id: string;                       // hash of package name@version + canonical advisory ID
  package: PackageId;
  advisoryId: string;               // canonical ID (prefer GHSA, then CVE, then OSV ID)
  aliases: string[];
  installedVersion: string;
  nodeIds: string[];                // every installed copy of this name@version
  direct: boolean;
  dev: boolean;
  upstreamSeverity: {
    cvssScore?: number;
    label?: string;
    source: "cvss-vector" | "label" | "none";
  };
  fixedVersions: string[];
  suggestedAction: string;          // e.g. "Upgrade X to >=1.2.4" or "Bump direct dependency D / add an override for X"
  dependencyPaths: string[][];      // shortest N paths only (see below)
  dependencyPathCount: number;      // total number of paths found
  riskScore: number | null;
  riskLevel: RiskLevel;
  factors: RiskFactor[];
  references: string[];
}
```

`riskScore: null` is intentional: missing severity data must not be silently interpreted as zero risk. Reports distinguish unknown risk from a verified low-risk finding.

**Dependency paths:** diamond-shaped graphs can have exponentially many paths. Store the shortest N (default 5, deterministic order: length, then lexicographic) and the total count.

**Deduplication:** one vulnerability often appears as both a GHSA and a CVE. Merge by package version + alias set, not by raw advisory ID. The same `name@version` installed in several places is one finding with several `nodeIds`.

### Scan result

```ts
export interface ScanResult {
  schemaVersion: "1.0";
  toolVersion: string;
  scanId: string;
  startedAt: string;
  completedAt: string;
  rootPath: string;
  status: "complete" | "partial" | "failed";
  coverage: {
    packagesScanned: number;
    queried: number;
    failed: number;      // lookups that errored
    skipped: number;     // non-registry packages etc.
  };
  advisoryData: {
    provider: "osv";
    freshLookups: number;
    cacheHits: number;
    staleCacheHits: number;     // offline use beyond TTL
    oldestFetchedAt?: string;
  };
  findings: Finding[];
  policy?: PolicyResult;        // present when policy was evaluated
  errors: {
    code: string;
    message: string;
  }[];
}
```

A completed scan with vulnerabilities is still a successful analysis. Whether it fails CI is a separate policy decision.

---

## 5. Risk scoring

The MVP uses a deterministic, documented prioritization heuristic, not an opaque or AI-generated score.

### Initial model

A 0–100 score from two scored factors; remediation is shown, not scored.

| Factor | Initial weight | Value (0–100) |
|---|---:|---|
| Advisory severity | 80% | `cvssScore * 10`. If only a label exists: CRITICAL=95, HIGH=80, MODERATE=55, LOW=20 (documented fallback). |
| Runtime exposure | 20% | Production dependency = 100, optional = 60, dev-only = 40. |

`risk = 0.80 * severity + 0.20 * exposure`

Rationale:

- **Direct vs transitive is not scored.** Whether a package is direct does not change how dangerous it is, only how easy it is to fix. It appears in the explanation and in the suggested action.
- **Fix availability is not scored.** It would be ambiguous whether a fix raises urgency or lowers it. It is surfaced as `fixedVersions` and `suggestedAction`.
- **Dev-only** dependencies are real but usually lower exposure, so they get a lower exposure value.

Risk level thresholds (initial, to be calibrated against fixtures and documented in `docs/risk-scoring.md`): `critical` ≥ 90, `high` ≥ 70, `medium` ≥ 40, `low` < 40. A finding with no usable severity is `unknown` with `riskScore: null`.

The model is a product heuristic, not a validated measurement of real-world exploitability. Document the rules, test them against labeled fixtures, and run sensitivity analysis before claiming the ranking is effective.

### Severity normalization

OSV provides CVSS **vector strings** (v3.x, sometimes v4) and sometimes only a label such as `database_specific.severity`, not a numeric score.

1. If a CVSS v3.x vector exists, compute the base score from it (library or small own implementation, covered by tests against known vectors). Prefer v3.x; use v4 only if the chosen library supports it.
2. Otherwise map the label using the table above.
3. Otherwise `source: "none"` and the finding is `unknown`.

### Scoring rules

- Keep upstream severity and CVSS metadata separate from Chainwatch's score.
- If severity is missing, return an unknown score rather than inventing one.
- Use deterministic tie-breaking: score desc, then package name, then version, then advisory ID.
- Do not claim code reachability, active exploitation, or malicious behavior without separate evidence.
- Make each score explainable by listing factor names, values, and reasons.

Example explanation:

```text
HIGH — example-library@1.2.3
Advisory: GHSA-xxxx-yyyy-zzzz (CVE-0000-0000)

Why it is prioritized:
  + High upstream advisory severity (CVSS 8.1)
  + Production dependency

Dependency path (1 of 1):
  application -> example-library@1.2.3

Recommended action:
  Upgrade example-library to >=1.2.4 (direct dependency).

Limitations:
  Runtime reachability has not been evaluated.
```

The example is illustrative. Actual findings and scores must be derived from advisory data and the implemented rules.

---

## 6. CLI commands

Keep the command surface small and each command focused.

| Command | Purpose |
|---|---|
| `chainwatch scan .` | Scan a repository |
| `chainwatch scan . --format json\|html\|sarif` | Emit a machine-readable or standalone report |
| `chainwatch explain <package> [--input scan.json]` | Explain findings and dependency paths for a package. With `--input`, reads a saved scan; otherwise runs a scan in memory. |
| `chainwatch report --input scan.json --format html` | Render an existing scan result without re-querying |
| `chainwatch --version` | Print the installed version |

Examples:

```bash
chainwatch scan .
chainwatch scan . --format json --output chainwatch-report.json
chainwatch scan . --format html --output report.html
chainwatch scan . --fail-on high
```

Options:

- `--offline`: use cached advisory data only. Cache misses make the scan `partial`. Cache entries older than the TTL are used but counted in `staleCacheHits`.
- `--no-cache`: bypass the advisory cache.
- `--config`: load repository-specific policy.
- `--verbose`: write diagnostics to stderr, never to stdout, so machine-readable output stays clean.
- `--fail-on <level>`: fail on findings whose **risk level** is at or above the level (`high` fails on high and critical).

### Exit codes

| Code | Meaning |
|---:|---|
| `0` | Scan complete and policy passed |
| `1` | Scan complete but security policy failed |
| `2` | Invalid arguments or configuration |
| `3` | Scan `partial` or `failed` due to operational errors (takes precedence over `1`) |

Exit `3` takes precedence over `1` so an incomplete scan is never reported as a normal policy result. The JSON output still contains all findings and the policy result, so nothing is hidden. CI users must be able to tell whether their code failed a security check or the security check itself failed.

---

## 7. Configuration

Use YAML for repository configuration and validate it with Zod. Reject invalid settings rather than silently ignoring them.

Example `chainwatch.example.yaml`:

```yaml
version: 1

scan:
  lockfiles:
    - package-lock.json
  includeDevDependencies: true

advisories:
  provider: osv
  cacheTtlSeconds: 3600

risk:
  weights:
    severity: 0.8
    exposure: 0.2

policy:
  failOn: high
  unknownSeverity: report   # report | fail
  ignore: []
```

These are illustrative defaults. Validate that weights are nonnegative and sum to one. Keep policy enforcement separate from the risk engine.

`unknownSeverity: report` lists unknown-risk findings but never fails CI; `fail` treats them as policy failures.

For allowlisted findings, require an advisory ID (matched against the finding's canonical ID **and aliases**), a reason, and an expiration date. Avoid permanent blanket exclusions such as ignoring all vulnerabilities from a particular package.

```yaml
policy:
  ignore:
    - advisoryId: GHSA-xxxx-yyyy-zzzz
      reason: "Tracked upstream issue; temporary exception"
      expires: "2026-12-31"
```

**Expired exceptions stop applying.** The finding counts toward policy again and a warning names the expired entry. A malformed configuration (missing reason or date, bad date, unknown keys) fails validation with exit `2`.

---

## 8. OSV integration, caching, and reliability

Use the [official OSV API](https://google.github.io/osv.dev/api/) as the initial advisory source. Keep it behind a small provider interface so another source can be added later without rewriting the analysis engine.

```ts
export interface AdvisoryProvider {
  /** Returns advisory IDs per package; throws or reports per-package errors, never returns [] on failure. */
  queryBatch(packages: PackageId[]): Promise<Map<string, string[]>>;
  getAdvisory(id: string): Promise<Advisory>;
}
```

The implementation must follow the API's supported request schema and limits. Verify against the current docs before building:

- `POST /v1/querybatch`: chunk to the documented maximum number of queries per request, and follow `next_page_token` for paginated results. Results contain IDs and `modified` only.
- `GET /v1/vulns/{id}`: full record, fetched for each distinct ID and cached by ID.

### Reliability requirements

- Batch requests where supported.
- Add timeouts and bounded retries with backoff for transient errors.
- Respect rate limits and avoid retry storms.
- Cache normalized advisory records by vulnerability ID, and package-query results (name@version → IDs) with a TTL and `fetchedAt`.
- Distinguish cached information from fresh results (`advisoryData` in the scan result).
- Report incomplete coverage when lookups fail (`coverage.failed`, status `partial`).
- Never interpret an empty response caused by an error as proof that a package is safe.

Start with a small file-based cache in the OS user cache directory. Adopt SQLite later only if transactional updates, concurrency, or invalidation genuinely require it.

### Privacy consideration

Sending package names and versions to a remote vulnerability API discloses some information about a project. Document this behavior and make offline cached scanning possible.

---

## 9. Security of Chainwatch itself

Chainwatch parses untrusted files and renders untrusted text, so it needs its own checks. These belong in `docs/threat-model.md` and the test suite.

- **Lockfile input:** enforce a maximum file size, validate with Zod, and use `Map` (not plain objects) for name lookups so keys such as `__proto__` cannot pollute anything.
- **HTML report:** package names, versions, and advisory summaries are untrusted. Escape every interpolated value, include no inline scripts, and add a restrictive CSP `<meta>`. Include a test with a hostile summary (`<script>`, attribute-breaking quotes).
- **Cache:** validate cache files with Zod on read. A corrupt or tampered entry is treated as a miss, never as "no vulnerabilities".
- **Terminal output:** strip control/escape sequences from untrusted strings before printing.
- **Never execute** install scripts or package code.

---

## 10. Testing strategy

Testing is part of the product, not a finishing task.

### Unit tests

Cover:

- Package normalization and lockfile edge cases (workspaces, `link`, aliases, bundled, optional/peer, non-registry sources, unsupported `lockfileVersion`).
- Semantic-version and affected-range matching, including `introduced`/`fixed`/`last_affected` events.
- CVSS vector → score, and label fallback.
- Dependency graph traversal, node resolution, and path reconstruction (including capped paths).
- Finding deduplication across aliases and duplicate installs.
- Risk scoring, missing severity, and deterministic tie-breaking.
- Configuration validation and policy evaluation (including expired exceptions).

### Integration tests

Use mocked HTTP responses to test:

- OSV `querybatch` parsing, pagination, and the follow-up record fetch.
- Cache hits, expiry, corruption, and offline behavior.
- Timeouts, retries, and rate-limit handling.
- Partial results and provider failures.
- Withdrawn advisories.

### Security regression fixtures

Create fixture repositories for:

- Known affected package versions.
- Patched versions.
- Transitive dependencies.
- Multiple versions of the same package.
- Missing severity metadata.
- Malformed lockfiles and missing advisory data.
- Non-registry dependencies.
- Hostile strings in advisory data (HTML report and terminal).

Generate fixture lockfiles with `npm install --package-lock-only` from small `package.json` files rather than hand-writing them, so they reflect real npm output.

### End-to-end tests

Run the compiled CLI against fixtures and verify findings, output, exit codes, and policy behavior.

### Tooling

- Vitest for unit and integration tests.
- TypeScript strict mode.
- ESLint (including import-boundary rules) and Prettier.
- GitHub Actions for linting, type-checking, tests, and builds.
- Fixed advisory fixtures for deterministic tests; ordinary unit tests must not depend on live OSV data.
- Optional property-based tests for version ranges and graph invariants.

### Release acceptance criteria

- A vulnerable fixture produces the expected finding.
- A patched fixture does not produce the same affected-version finding.
- A GHSA/CVE pair for one vulnerability yields one finding.
- Transitive dependency paths are correct, and diamond graphs do not blow up.
- Multiple versions of one package are handled independently.
- Non-registry packages are reported as skipped, not clean.
- Missing severity produces an unknown score.
- API failures cannot silently become clean scans.
- Exit codes reflect policy rather than mere scan completion; `3` takes precedence over `1`.
- Expired exceptions no longer suppress findings.
- The HTML report is XSS-safe against the hostile fixture.
- JSON output conforms to the generated, documented schema.
- A clean checkout can install, test, build, and run the CLI using the README.

---

## 11. Implementation phases

Build in dependency order. Do not build reports before the scan result model exists or risk scoring before advisory matching works. Start a phase only when the previous phase's exit criterion is met.

### Phase 1 — Foundation and npm dependency graph

- Initialize the single package, strict TypeScript, lint/test/build scripts, and import-boundary lint rules.
- Implement CLI scaffold and configuration validation.
- Parse `package-lock.json` (v2/v3) into normalized packages and edges, including workspaces, aliases, and non-registry detection.
- Test direct/transitive/dev classification and multiple package versions.

**Exit criterion:** Chainwatch can scan a local npm lockfile and print a correct dependency graph.

### Phase 2 — Advisory integration and cache

- Implement the OSV provider and Zod response schemas (`querybatch`, pagination, record fetch).
- Add batching, timeouts, retries, and error handling.
- Add the file-based cache and `--offline` / `--no-cache` behavior.
- Implement affected-range matching for offline use.
- Add deterministic advisory fixtures and integration tests.

**Exit criterion:** Chainwatch identifies known vulnerabilities in a controlled fixture, distinguishes patched versions, and reports partial coverage on failure.

### Phase 3 — Risk engine

- Normalize upstream severity (CVSS vector → score, label fallback).
- Implement documented scoring and deterministic ranking.
- Deduplicate findings by alias set while preserving capped dependency paths.
- Implement `chainwatch explain` and risk-factor output.

**Exit criterion:** Each finding has evidence, a dependency path, and a reproducible explanation of its ranking.

### Phase 4 — Reports and remediation

- Implement terminal, JSON (with generated schema), and HTML reports, plus `chainwatch report --input`.
- Add fixed-version guidance and suggested actions when metadata supports it.
- Add HTML escaping/CSP and terminal sanitization with their tests.
- Validate reports against vulnerable and patched fixtures.

**Exit criterion:** A developer can use the scanner locally and export usable reports without a hosted service.

### Phase 5 — CI and policy

- Implement configurable `fail-on` thresholds, `unknownSeverity`, and exceptions with expiry.
- Finalize exit-code precedence and test partial scans and malformed configuration.
- Add a GitHub Actions example and machine-readable artifacts.
- Stretch: SARIF output for GitHub code scanning.
- Run security and regression tests in CI.

**Exit criterion:** A repository can enforce Chainwatch policy in a pull-request workflow.

### Phase 6 — Release quality

- Benchmark representative repositories and document results.
- Write threat model, architecture decisions, scoring methodology, and limitations.
- Test clean installation and package distribution.
- Publish a tagged release, demo, and complete README.

**Exit criterion:** A reproducible open-source release with a defensible demo and measurable evaluation.

### Working agreement for every phase

- Phases run strictly in order. Each one is implemented, then polished and optimized (cleanup, naming, error messages, performance of hot paths), then closed against its exit criterion before the next starts.
- Work happens on the `dev` branch, with several small commits per phase instead of one large one.
- Commit messages are plain, human-written sentences describing what changed and why (for example, "Handle workspace links when resolving lockfile dependencies"). No conventional-commit prefixes such as `feat:` or `fix:`, no scopes, no emoji.
- Commits and pushes are made as the repository owner's own GitHub account, with no tool or co-author attribution lines.

If scope must be cut, preserve the parser, advisory matching, dependency paths, explainable scoring, tests, and CI behavior. Drop SARIF first, then the HTML report, before sacrificing correctness.

---

## 12. Initial repository setup

Start minimal. Do not create every module before the first vertical slice works.

PowerShell:

```powershell
mkdir chainwatch; cd chainwatch
npm init -y
npm pkg set private=true type=module
New-Item -ItemType Directory -Force src/cli/commands, src/core, src/lockfile, src/advisories, src/risk, src/policy, src/reports, tests/unit, tests/integration, tests/e2e, tests/fixtures/vulnerable, tests/fixtures/patched, tests/fixtures/malformed, docs/decisions, .github/workflows
```

Bash (Git Bash / macOS / Linux):

```bash
mkdir chainwatch && cd chainwatch
npm init -y
npm pkg set private=true type=module
mkdir -p src/{cli/commands,core,lockfile,advisories,risk,policy,reports} \
  tests/{unit,integration,e2e,fixtures/{vulnerable,patched,malformed}} \
  docs/decisions .github/workflows
```

Pin the Node.js version in `.nvmrc`, `engines`, and CI. Configure root build, lint, type-check, and test scripts early.

### First coding session

Implement only:

1. The package and CLI scaffold, with import-boundary lint rules.
2. The `PackageId`, `DependencyNode`, `DependencyEdge`, and `DependencyGraph` types.
3. The npm lockfile parser and graph builder with tests against a small fixture generated by `npm install --package-lock-only`.

Do not generate every module at once. Build the first vertical slice, make it pass, and then add advisory integration.

---

## 13. Resume positioning

After the project is implemented and evaluated, a concise resume entry could read:

> **Chainwatch — Open-Source Dependency Risk Analyzer**  
> Built a TypeScript CLI for npm dependency analysis, integrating OSV vulnerability intelligence with dependency-graph traversal, explainable risk prioritization, remediation guidance, and CI security policies. Added deterministic regression fixtures, machine-readable reporting, and fault-tolerant advisory lookups.

Only add measured metrics after evaluating the implementation, for example package count, scan latency, cache effectiveness, or detection precision against a labeled test corpus. Do not invent performance numbers or claim runtime reachability unless it has actually been implemented and evaluated.

---

## Final architecture decision

**Single TypeScript package with enforced internal module boundaries, npm-only initial ecosystem (lockfile v2/v3), OSV as the advisory provider, an in-memory dependency graph, deterministic two-factor risk scoring, local file caching, and CLI/CI as the primary interfaces.** Keep the analysis engine independent of presentation and enforcement. This keeps the phased plan realistic and provides a sound foundation for future ecosystems, workspace-package splitting, and deeper analysis.
