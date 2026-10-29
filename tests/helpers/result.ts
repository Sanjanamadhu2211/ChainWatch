import type { Finding, ScanResult } from "../../src/core/types";

export const finding = (overrides: Partial<Finding> = {}): Finding => ({
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

export const result = (overrides: Partial<ScanResult> = {}): ScanResult => ({
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
