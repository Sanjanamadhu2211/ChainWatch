import { randomUUID } from "node:crypto";
import pkg from "../../package.json";
import { AdvisoryCache, defaultCacheDir, type CacheEntry } from "../advisories/cache";
import { OsvClient } from "../advisories/osv-client";
import { packageKey, type AdvisoryProvider } from "../advisories/provider";
import { evaluatePolicy, type FailOn } from "../policy/evaluate";
import { buildFindings, type AffectedPackage } from "./findings";
import { loadProject } from "./project";
import type { Advisory, DependencyNode, ScanError, ScanResult } from "./types";

export interface ScanOptions {
  path: string;
  configPath?: string;
  /** Use only cached advisory data; never touch the network. */
  offline?: boolean;
  /** Ignore and do not write the on-disk cache. */
  noCache?: boolean;
  provider?: AdvisoryProvider;
  cacheDir?: string;
  /** Overrides the configured failOn level (the --fail-on flag). */
  failOn?: FailOn;
  now?: () => Date;
  /** Diagnostics for --verbose. Written by the caller to stderr so reports stay machine-readable. */
  log?: (message: string) => void;
}

const MAX_NAMES_IN_MESSAGE = 10;

/**
 * Runs a full scan and returns the normalized result, including the policy decision.
 * The CLI maps the result to an exit code.
 */
export async function runScan(options: ScanOptions): Promise<ScanResult> {
  const now = options.now ?? (() => new Date());
  const startedAt = now();
  const project = await loadProject(options.path, options.configPath);
  const { graph } = project.lockfile;
  const log = options.log ?? (() => {});
  log(`Read ${project.lockfilePath} (${graph.nodes.length} installed packages)`);
  const warnings = [...project.lockfile.warnings];
  const ttlMs = project.config.advisories.cacheTtlSeconds * 1000;
  const offline = options.offline === true;

  // Only registry packages can be looked up. Workspace members are first-party code.
  const groups = new Map<string, DependencyNode[]>();
  const nonRegistry: string[] = [];
  let skipped = 0;
  for (const node of graph.nodes) {
    if (node.source === "registry") {
      const key = packageKey(node.package);
      groups.set(key, [...(groups.get(key) ?? []), node]);
    } else {
      skipped++;
      if (node.source === "non-registry") nonRegistry.push(packageKey(node.package));
    }
  }
  if (nonRegistry.length > 0) {
    warnings.push(
      `${nonRegistry.length} package(s) from non-registry sources (git, file, tarball) were not checked: ` +
        listNames(nonRegistry),
    );
  }

  const cache = options.noCache
    ? AdvisoryCache.empty()
    : await AdvisoryCache.load(options.cacheDir ?? defaultCacheDir());
  if (cache.corrupt) warnings.push("The advisory cache could not be read and was ignored.");
  const provider = options.provider ?? (offline ? undefined : new OsvClient());

  let freshLookups = 0;
  let cacheHits = 0;
  let staleCacheHits = 0;
  let oldest = startedAt;
  const failures = new Map<string, ScanError>(); // package key -> why it could not be checked
  const fail = (key: string, code: string, error: string) =>
    failures.set(key, { code, message: error });

  /** Serves a cache entry if allowed. Offline accepts entries of any age; online only fresh ones. */
  const fromCache = <T>(entry: CacheEntry<T> | undefined): T | undefined => {
    if (!entry) return undefined;
    const fresh = startedAt.getTime() - entry.fetchedAt.getTime() <= ttlMs;
    if (!fresh && !offline) return undefined;
    cacheHits++;
    if (!fresh) staleCacheHits++;
    if (entry.fetchedAt < oldest) oldest = entry.fetchedAt;
    return entry.value;
  };

  // 1. Which advisory ids affect each package?
  const idsByKey = new Map<string, string[]>();
  const toQuery: DependencyNode["package"][] = [];
  for (const [key, nodes] of groups) {
    const cached = fromCache(cache.getQuery(key));
    if (cached) idsByKey.set(key, cached);
    else if (offline || !provider)
      fail(key, "OFFLINE_CACHE_MISS", "not in the local cache (offline mode)");
    else toQuery.push((nodes[0] as DependencyNode).package);
  }
  log(
    `${idsByKey.size} of ${groups.size} packages answered from cache; ${toQuery.length} to query`,
  );
  if (toQuery.length > 0 && provider) {
    for (const [key, lookup] of await provider.queryBatch(toQuery)) {
      if (lookup.ok) {
        idsByKey.set(key, lookup.value);
        cache.setQuery(key, lookup.value, startedAt);
        freshLookups++;
      } else {
        fail(key, "ADVISORY_LOOKUP_FAILED", lookup.error);
      }
    }
    for (const p of toQuery) {
      const key = packageKey(p);
      if (!idsByKey.has(key) && !failures.has(key))
        fail(key, "ADVISORY_LOOKUP_FAILED", "no answer from the provider");
    }
  }

  // 2. Fetch the advisory records behind those ids.
  const keysById = new Map<string, string[]>();
  for (const [key, ids] of idsByKey)
    for (const id of ids) keysById.set(id, [...(keysById.get(id) ?? []), key]);

  log(`${keysById.size} distinct advisories referenced`);
  const advisories = new Map<string, Advisory>();
  const toFetch: string[] = [];
  for (const id of keysById.keys()) {
    const cached = fromCache(cache.getAdvisory(id));
    if (cached) advisories.set(id, cached);
    else if (offline || !provider)
      for (const key of keysById.get(id) ?? [])
        fail(key, "OFFLINE_CACHE_MISS", `advisory ${id} is not in the local cache (offline mode)`);
    else toFetch.push(id);
  }
  if (toFetch.length > 0 && provider) {
    for (const [id, lookup] of await provider.getAdvisories(toFetch)) {
      if (lookup.ok) {
        advisories.set(id, lookup.value);
        cache.setAdvisory(lookup.value, startedAt);
        freshLookups++;
      } else {
        for (const key of keysById.get(id) ?? [])
          fail(key, "ADVISORY_LOOKUP_FAILED", `advisory ${id}: ${lookup.error}`);
      }
    }
  }

  // 3. Findings, from whatever was successfully retrieved.
  const affected: AffectedPackage[] = [];
  for (const [key, ids] of idsByKey) {
    const found = ids.flatMap((id) => advisories.get(id) ?? []);
    if (found.length > 0)
      affected.push({ nodes: groups.get(key) as DependencyNode[], advisories: found });
  }
  const findings = buildFindings(graph, affected, project.config.risk.weights);
  const policy = evaluatePolicy(findings, project.config.policy, {
    failOn: options.failOn ?? project.config.policy.failOn,
    now: startedAt,
  });

  if (!offline && !(await cache.save(startedAt))) {
    warnings.push("The advisory cache could not be written; the next scan will query OSV again.");
  }

  const queried = groups.size;
  return {
    schemaVersion: "1.0",
    toolVersion: pkg.version,
    scanId: randomUUID(),
    startedAt: startedAt.toISOString(),
    completedAt: now().toISOString(),
    rootPath: project.rootPath,
    status: failures.size === 0 ? "complete" : failures.size >= queried ? "failed" : "partial",
    coverage: { packagesScanned: graph.nodes.length, queried, failed: failures.size, skipped },
    advisoryData: {
      provider: "osv",
      freshLookups,
      cacheHits,
      staleCacheHits,
      ...(cacheHits > 0 ? { oldestFetchedAt: oldest.toISOString() } : {}),
    },
    findings,
    policy,
    warnings,
    errors: summarizeFailures(failures),
  };
}

function listNames(names: string[]): string {
  const shown = names.slice(0, MAX_NAMES_IN_MESSAGE).join(", ");
  return names.length > MAX_NAMES_IN_MESSAGE
    ? `${shown}, and ${names.length - MAX_NAMES_IN_MESSAGE} more`
    : shown;
}

/** One error per distinct cause, naming a few of the packages affected. */
function summarizeFailures(failures: Map<string, ScanError>): ScanError[] {
  const byCause = new Map<string, { code: string; keys: string[] }>();
  for (const [key, { code, message }] of failures) {
    const entry = byCause.get(message) ?? { code, keys: [] };
    entry.keys.push(key);
    byCause.set(message, entry);
  }
  return [...byCause].map(([message, { code, keys }]) => ({
    code,
    message: `${keys.length} package(s) could not be checked: ${message} (${listNames(keys)})`,
  }));
}
