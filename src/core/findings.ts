import { createHash } from "node:crypto";
import semver from "semver";
import { normalizeSeverity } from "../advisories/cvss";
import { fixedVersionsFor } from "../advisories/matching";
import { indexGraph, shortestPaths, type GraphIndex } from "../lockfile/graph";
import { rankFindings } from "../risk/ranking";
import { scoreFinding, type RiskWeights } from "../risk/scoring";
import type { Advisory, DependencyGraph, DependencyNode, Finding } from "./types";

/** An installed name@version (possibly in several places) and the advisories OSV reported for it. */
export interface AffectedPackage {
  nodes: DependencyNode[];
  advisories: Advisory[];
}

/** Advisories that share any id or alias are the same vulnerability under different names. */
function mergeByAlias(advisories: Advisory[]): Advisory[][] {
  const groups: { ids: Set<string>; members: Advisory[] }[] = [];
  for (const advisory of advisories) {
    const names = [advisory.id, ...advisory.aliases];
    const hits = groups.filter((g) => names.some((n) => g.ids.has(n)));
    const target = hits[0] ?? { ids: new Set<string>(), members: [] };
    if (!hits.length) groups.push(target);
    for (const other of hits.slice(1)) {
      other.ids.forEach((n) => target.ids.add(n));
      target.members.push(...other.members);
      groups.splice(groups.indexOf(other), 1);
    }
    names.forEach((n) => target.ids.add(n));
    target.members.push(advisory);
  }
  return groups.map((g) => g.members);
}

/** GHSA first, then CVE, then the first id alphabetically. */
function canonicalId(ids: string[]): string {
  const sorted = [...ids].sort();
  return (
    sorted.find((i) => i.startsWith("GHSA-")) ??
    sorted.find((i) => i.startsWith("CVE-")) ??
    (sorted[0] as string)
  );
}

export function suggestAction(
  name: string,
  fixed: string[],
  directDependency: string | undefined,
): string {
  const fix = fixed[0];
  if (fix === undefined) {
    return "No fixed version is listed in the advisory. Check its references for mitigations.";
  }
  if (directDependency === undefined) return `Upgrade ${name} to ${fix} or later.`;
  return (
    `Update ${directDependency} to a release that depends on ${name} ${fix} or later, ` +
    `or add an override for ${name}.`
  );
}

export function buildFindings(
  graph: DependencyGraph,
  affected: Iterable<AffectedPackage>,
  weights: RiskWeights,
): Finding[] {
  const index: GraphIndex = indexGraph(graph);
  const findings: Finding[] = [];

  for (const { nodes, advisories } of affected) {
    const pkg = (nodes[0] as DependencyNode).package;
    const nodeIds = nodes.map((n) => n.id).sort();
    const { paths, count } = shortestPaths(index, nodeIds);
    const direct = nodes.some((n) => n.direct);
    // The first hop after the project is the direct dependency that pulls the package in.
    const via = direct ? undefined : paths[0]?.[1];

    for (const group of mergeByAlias(advisories.filter((a) => a.withdrawn === undefined))) {
      const allIds = [...new Set(group.flatMap((a) => [a.id, ...a.aliases]))];
      const advisoryId = canonicalId(allIds);
      const fixedVersions = [
        ...new Set(group.flatMap((a) => fixedVersionsFor(a, pkg.name, pkg.version))),
      ].sort(semver.compare);
      const summary = group.find((a) => a.summary)?.summary;

      const dev = nodes.every((n) => n.dev);
      const optional = nodes.every((n) => n.optional);
      const upstreamSeverity = normalizeSeverity(group);

      findings.push({
        id: createHash("sha256")
          .update(`${pkg.name}@${pkg.version}|${advisoryId}`)
          .digest("hex")
          .slice(0, 16),
        package: pkg,
        advisoryId,
        aliases: allIds.filter((i) => i !== advisoryId).sort(),
        ...(summary ? { summary } : {}),
        installedVersion: pkg.version,
        nodeIds,
        direct,
        dev,
        optional,
        upstreamSeverity,
        fixedVersions,
        suggestedAction: suggestAction(pkg.name, fixedVersions, via),
        dependencyPaths: paths,
        dependencyPathCount: count,
        ...scoreFinding({ upstreamSeverity, dev, optional }, weights),
        references: [...new Set(group.flatMap((a) => a.references))],
      });
    }
  }

  return rankFindings(findings);
}
