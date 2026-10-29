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
  /** Declared by the root project or one of its workspaces. */
  direct: boolean;
  /** Reachable only through devDependencies. */
  dev: boolean;
  optional: boolean;
  peer: boolean;
  /** Only "registry" nodes are looked up in the advisory database. */
  source: "registry" | "workspace" | "non-registry";
}

export interface DependencyEdge {
  from: string;
  to: string;
  /** Declared semver range, kept for remediation hints. */
  range: string;
  type: "prod" | "dev" | "optional" | "peer";
}

export interface DependencyGraph {
  /** The project itself. Its id in edges is ROOT_ID. */
  root: { name: string; version: string };
  nodes: DependencyNode[];
  edges: DependencyEdge[];
}

export const ROOT_ID = "";

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
  id: string;
  aliases: string[];
  summary?: string;
  /** Present when the advisory was withdrawn; such advisories are dropped. */
  withdrawn?: string;
  severity: {
    cvssVectors: { type: string; vector: string }[];
    /** e.g. database_specific.severity: LOW | MODERATE | HIGH | CRITICAL */
    label?: string;
  };
  affected: {
    packageName: string;
    versions: string[];
    ranges: AffectedRange[];
  }[];
  references: string[];
  modifiedAt?: string;
}

export type RiskLevel = "critical" | "high" | "medium" | "low" | "unknown";

export interface RiskFactor {
  name: string;
  contribution: number;
  reason: string;
}

export interface Finding {
  /** Hash of package name@version plus the canonical advisory id. */
  id: string;
  package: PackageId;
  /** Canonical id: GHSA first, then CVE, then whatever the source used. */
  advisoryId: string;
  aliases: string[];
  summary?: string;
  installedVersion: string;
  /** Every installed copy of this name@version. */
  nodeIds: string[];
  direct: boolean;
  dev: boolean;
  optional: boolean;
  upstreamSeverity: {
    cvssScore?: number;
    label?: string;
    source: "cvss-vector" | "label" | "none";
  };
  fixedVersions: string[];
  suggestedAction: string;
  /** Shortest paths only, rendered as name@version labels. */
  dependencyPaths: string[][];
  /** Number of shortest paths from the project to the package. */
  dependencyPathCount: number;
  riskScore: number | null;
  riskLevel: RiskLevel;
  factors: RiskFactor[];
  references: string[];
}

export interface ScanError {
  code: string;
  message: string;
}

export interface PolicyResult {
  passed: boolean;
  failOn: RiskLevel | "none";
  failingFindingIds: string[];
  ignoredFindingIds: string[];
  warnings: string[];
}

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
    /** Lookups that errored. */
    failed: number;
    /** Workspace and non-registry packages. */
    skipped: number;
  };
  advisoryData: {
    provider: "osv";
    freshLookups: number;
    cacheHits: number;
    /** Cache entries used past their TTL (offline mode). */
    staleCacheHits: number;
    oldestFetchedAt?: string;
  };
  findings: Finding[];
  policy?: PolicyResult;
  /** Problems that do not change the scan status, such as packages that could not be checked by design. */
  warnings: string[];
  errors: ScanError[];
}
