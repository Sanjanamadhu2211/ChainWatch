import { strict as assert } from "node:assert";
import type { Finding, ScanResult } from "../src/core/types";
import { renderHtml } from "../src/reports/html";

const finding: Finding = {
  id: "one",
  package: { ecosystem: "npm", name: "<unsafe>", version: "1.0.0" },
  advisoryId: "OSV-1",
  aliases: [],
  installedVersion: "1.0.0",
  nodeIds: [],
  direct: true,
  dev: false,
  optional: false,
  upstreamSeverity: { source: "none" },
  fixedVersions: [],
  suggestedAction: "Update",
  dependencyPaths: [],
  dependencyPathCount: 0,
  riskScore: 50,
  riskLevel: "high",
  factors: [],
  references: ["javascript:alert(1)"],
};
const result: ScanResult = {
  schemaVersion: "1.0",
  toolVersion: "1",
  scanId: "id",
  startedAt: "now",
  completedAt: "now",
  rootPath: "project",
  status: "partial",
  coverage: { packagesScanned: 2, queried: 1, failed: 1, skipped: 0 },
  advisoryData: { provider: "osv", freshLookups: 1, cacheHits: 0, staleCacheHits: 0 },
  findings: [finding, { ...finding, id: "two", riskLevel: "unknown" }],
  warnings: [],
  errors: [],
};
const html = renderHtml(result);
assert.match(html, /High<\/span>\s*<strong>1<\/strong>/);
assert.match(html, /Unknown<\/span>\s*<strong>1<\/strong>/);
assert.match(html, /Partial/);
assert.match(html, /&lt;unsafe&gt;/);
assert.doesNotMatch(html, /href="javascript:/);
assert.match(html, /default-src 'none'/);
assert.match(html, /prefers-color-scheme: dark/);
