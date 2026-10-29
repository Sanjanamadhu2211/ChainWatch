import type { Advisory, PackageId } from "../core/types";

/** A lookup either succeeded or failed with a reason. A failure is never an empty result. */
export type Lookup<T> = { ok: true; value: T } | { ok: false; error: string };

export interface AdvisoryProvider {
  /** Advisory ids that affect each package, keyed by packageKey(). */
  queryBatch(packages: PackageId[]): Promise<Map<string, Lookup<string[]>>>;
  /** Full advisory records, keyed by id. */
  getAdvisories(ids: string[]): Promise<Map<string, Lookup<Advisory>>>;
}

export function packageKey(p: Pick<PackageId, "name" | "version">): string {
  return `${p.name}@${p.version}`;
}
