import semver from "semver";
import type { Advisory, AffectedRange } from "../core/types";

/**
 * Whether `version` falls inside an OSV range, following the event algorithm in the OSV schema:
 * walk the events in ascending order; `introduced` turns "affected" on, `fixed` and
 * `last_affected` turn it off. Returns undefined when the range cannot be evaluated (GIT ranges
 * or versions that are not valid semver).
 */
export function inRange(range: AffectedRange, version: string): boolean | undefined {
  if (range.type === "GIT" || !semver.valid(version)) return undefined;
  const events = range.events
    .map((e) => ({ e, at: e.introduced ?? e.fixed ?? e.last_affected }))
    .filter((x): x is { e: typeof x.e; at: string } => x.at !== undefined)
    .sort((a, b) => cmp(a.at, b.at));
  let affected = false;
  for (const { e } of events) {
    if (e.introduced !== undefined && cmp(version, e.introduced) >= 0) affected = true;
    if (e.fixed !== undefined && cmp(version, e.fixed) >= 0) affected = false;
    if (e.last_affected !== undefined && cmp(version, e.last_affected) > 0) affected = false;
  }
  return affected;
}

// "0" is OSV's marker for "from the very first version"
function cmp(a: string, b: string): number {
  if (a === "0") return b === "0" ? 0 : -1;
  if (b === "0") return 1;
  const va = semver.valid(a);
  const vb = semver.valid(b);
  return va && vb ? semver.compare(va, vb) : a < b ? -1 : a > b ? 1 : 0;
}

/**
 * The lowest fixed version above `version` in every range that affects it, merged across the
 * advisory's entries for this package only (other packages in the record are ignored).
 */
export function fixedVersionsFor(advisory: Advisory, name: string, version: string): string[] {
  const fixed = new Set<string>();
  for (const entry of advisory.affected) {
    if (entry.packageName !== name) continue;
    for (const range of entry.ranges) {
      if (inRange(range, version) !== true) continue;
      const above = range.events
        .map((e) => e.fixed)
        .filter(
          (f): f is string => f !== undefined && semver.valid(f) !== null && semver.gt(f, version),
        )
        .sort(semver.compare);
      if (above[0] !== undefined) fixed.add(above[0]);
    }
  }
  return [...fixed].sort(semver.compare);
}
