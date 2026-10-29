import { describe, expect, it } from "vitest";
import type { Finding, ScanResult } from "../../src/core/types";
import { renderExplain, renderTerminal } from "../../src/reports/terminal";

const finding = (overrides: Partial<Finding> = {}): Finding => ({
  id: "f1",
  package: { ecosystem: "npm", name: "minimist", version: "0.0.8" },
  advisoryId: "GHSA-xvch-5gv4-984h",
  aliases: ["CVE-2021-44906"],
  summary: "Prototype Pollution in minimist",
  installedVersion: "0.0.8",
  nodeIds: ["node_modules/minimist"],
  direct: false,
  dev: false,
  optional: false,
  upstreamSeverity: { cvssScore: 9.8, label: "CRITICAL", source: "cvss-vector" },
  fixedVersions: ["0.2.4"],
  suggestedAction: "Upgrade minimist to >=0.2.4 (transitive dependency).",
  dependencyPaths: [["vulnerable-app", "mkdirp@0.5.1", "minimist@0.0.8"]],
  dependencyPathCount: 1,
  riskScore: 87.9,
  riskLevel: "high",
  factors: [
    { name: "Advisory severity", contribution: 78.4, reason: "CVSS v3 base score 9.8" },
    { name: "Runtime exposure", contribution: 20, reason: "Production dependency" },
  ],
  references: [],
  ...overrides,
});

const result = (overrides: Partial<ScanResult> = {}): ScanResult => ({
  schemaVersion: "1.0",
  toolVersion: "0.1.0",
  scanId: "s1",
  startedAt: "2026-01-01T00:00:00Z",
  completedAt: "2026-01-01T00:00:01Z",
  rootPath: "/project",
  status: "complete",
  coverage: { packagesScanned: 3, queried: 3, failed: 0, skipped: 0 },
  advisoryData: { provider: "osv", freshLookups: 3, cacheHits: 0, staleCacheHits: 0 },
  findings: [],
  warnings: [],
  errors: [],
  ...overrides,
});

describe("renderTerminal", () => {
  it("shows the risk level and score on each finding line", () => {
    const out = renderTerminal(result({ findings: [finding()] }));
    expect(out).toContain("1 finding(s):");
    expect(out).toContain(
      "HIGH (score 87.9)  minimist@0.0.8  GHSA-xvch-5gv4-984h (CVE-2021-44906)",
    );
  });

  it("marks a finding without severity data as unknown", () => {
    const out = renderTerminal(
      result({ findings: [finding({ riskScore: null, riskLevel: "unknown" })] }),
    );
    expect(out).toContain("UNKNOWN (no score)  minimist@0.0.8");
  });

  it("says the scan is not clean when status is not complete", () => {
    const out = renderTerminal(
      result({
        status: "partial",
        errors: [{ code: "OSV_FAILED", message: "lookup failed" }],
      }),
    );
    expect(out).toContain("error [OSV_FAILED]: lookup failed");
    expect(out).toContain("The scan is partial: this is NOT a clean result.");
    expect(out).not.toContain("No known vulnerabilities found.");
  });

  it("escapes control characters so advisory text cannot rewrite the terminal", () => {
    const out = renderTerminal(
      result({ findings: [finding({ summary: "bad\u001b[2J\nline" })] }),
    );
    expect(out).toContain("bad\\u001b[2J\\u000aline");
    expect(out).not.toContain("\u001b");
  });
});

describe("renderExplain", () => {
  it("prints the detailed sections for a matching finding", () => {
    const out = renderExplain(result(), [finding()], "minimist@0.0.8");
    expect(out).toContain("HIGH (score 87.9) - minimist@0.0.8");
    expect(out).toContain("Advisory: GHSA-xvch-5gv4-984h (CVE-2021-44906)");
    expect(out).toContain("Why it is prioritized:");
    expect(out).toContain("  + Advisory severity: CVSS v3 base score 9.8 (contributes 78.4)");
    expect(out).toContain("Dependency path (1 of 1):");
    expect(out).toContain("  vulnerable-app -> mkdirp@0.5.1 -> minimist@0.0.8");
    expect(out).toContain("Recommended action:\n  Upgrade minimist to >=0.2.4");
    expect(out).toContain("Limitations:\n  Runtime reachability has not been evaluated.");
  });

  it("prints a no-match message for a clean complete scan", () => {
    const out = renderExplain(result(), [], "lodash");
    expect(out).toBe("No known vulnerabilities found for lodash.");
  });

  it("qualifies the no-match message when the scan was not complete", () => {
    const out = renderExplain(result({ status: "failed" }), [], "lodash");
    expect(out).toContain(
      "No known vulnerabilities found for lodash in the packages that were checked.",
    );
    expect(out).toContain("The scan is failed: this is NOT a clean result.");
  });

  it("separates several matching findings with a blank line", () => {
    const out = renderExplain(
      result(),
      [finding(), finding({ advisoryId: "GHSA-vh95-rmgr-6w4m" })],
      "minimist",
    );
    expect(out).toContain("GHSA-xvch-5gv4-984h");
    expect(out).toContain("\n\nHIGH (score 87.9) - minimist@0.0.8\nAdvisory: GHSA-vh95-rmgr-6w4m");
  });
});
