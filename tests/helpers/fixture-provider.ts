import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parseOsvVuln } from "../../src/advisories/schema";
import { packageKey, type AdvisoryProvider, type Lookup } from "../../src/advisories/provider";
import type { Advisory, PackageId } from "../../src/core/types";

const osvDir = join(__dirname, "..", "fixtures", "osv");
const queries = JSON.parse(readFileSync(join(osvDir, "queries.json"), "utf8")) as Record<
  string,
  string[]
>;

export const loadVuln = (id: string): unknown =>
  JSON.parse(readFileSync(join(osvDir, "vulns", `${id}.json`), "utf8"));

export interface FixtureProviderOptions {
  /** Package keys (name@version) whose lookup should fail. */
  failPackages?: string[];
  failAll?: boolean;
  failAdvisories?: string[];
  /** Advisories to serve instead of the captured files. */
  advisories?: Advisory[];
  /** Advisory ids to return per package key instead of the captured answers. */
  ids?: Record<string, string[]>;
}

/** Replays captured OSV answers. Packages that were not captured have no advisories. */
export class FixtureProvider implements AdvisoryProvider {
  queryCalls = 0;
  advisoryCalls = 0;

  constructor(private readonly options: FixtureProviderOptions = {}) {}

  async queryBatch(packages: PackageId[]): Promise<Map<string, Lookup<string[]>>> {
    this.queryCalls++;
    const out = new Map<string, Lookup<string[]>>();
    for (const p of packages) {
      const key = packageKey(p);
      if (this.options.failAll || this.options.failPackages?.includes(key)) {
        out.set(key, { ok: false, error: "OSV responded with HTTP 503 after 4 attempts" });
      } else {
        out.set(key, { ok: true, value: this.options.ids?.[key] ?? queries[key] ?? [] });
      }
    }
    return out;
  }

  async getAdvisories(ids: string[]): Promise<Map<string, Lookup<Advisory>>> {
    this.advisoryCalls++;
    const out = new Map<string, Lookup<Advisory>>();
    for (const id of ids) {
      const custom = this.options.advisories?.find((a) => a.id === id);
      if (this.options.failAdvisories?.includes(id)) out.set(id, { ok: false, error: "HTTP 500" });
      else out.set(id, { ok: true, value: custom ?? parseOsvVuln(loadVuln(id)) });
    }
    return out;
  }
}
