import { mkdtemp, readdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import { AdvisoryCache, defaultCacheDir } from "../../src/advisories/cache";
import { parseOsvVuln } from "../../src/advisories/schema";
import { loadVuln } from "../helpers/fixture-provider";

let dir: string;
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "chainwatch-cache-"));
});

const now = new Date("2026-06-01T12:00:00Z");

describe("AdvisoryCache", () => {
  it("round-trips queries and advisories through disk", async () => {
    const cache = await AdvisoryCache.load(dir);
    cache.setQuery("lodash@4.17.15", ["GHSA-1"], now);
    cache.setAdvisory(parseOsvVuln(loadVuln("GHSA-35jh-r3h4-6jhm")), now);
    expect(await cache.save(now)).toBe(true);

    const reloaded = await AdvisoryCache.load(dir);
    expect(reloaded.corrupt).toBe(false);
    expect(reloaded.getQuery("lodash@4.17.15")).toEqual({ value: ["GHSA-1"], fetchedAt: now });
    expect(reloaded.getAdvisory("GHSA-35jh-r3h4-6jhm")?.value.aliases).toContain("CVE-2021-23337");
    expect(reloaded.getQuery("nope@1.0.0")).toBeUndefined();
    // the temp file used for the atomic write is gone
    expect(await readdir(dir)).toEqual(["osv-cache.json"]);
  });

  it("treats a missing file as an empty cache", async () => {
    const cache = await AdvisoryCache.load(join(dir, "does-not-exist"));
    expect(cache.corrupt).toBe(false);
    expect(cache.getQuery("a@1.0.0")).toBeUndefined();
  });

  it.each([
    ["invalid JSON", "{ not json"],
    [
      "the wrong shape",
      JSON.stringify({ version: 1, queries: { "a@1": { ids: "x" } }, advisories: {} }),
    ],
    [
      "a bad timestamp",
      JSON.stringify({
        version: 1,
        queries: { "a@1": { ids: [], fetchedAt: "yesterday" } },
        advisories: {},
      }),
    ],
    ["an unknown version", JSON.stringify({ version: 2, queries: {}, advisories: {} })],
  ])("ignores a cache file with %s instead of trusting it", async (_name, content) => {
    await writeFile(join(dir, "osv-cache.json"), content);
    const cache = await AdvisoryCache.load(dir);
    expect(cache.corrupt).toBe(true);
    expect(cache.getQuery("a@1")).toBeUndefined();
  });

  it("drops entries older than 30 days when saving", async () => {
    const cache = await AdvisoryCache.load(dir);
    cache.setQuery("old@1.0.0", [], new Date("2026-04-01T00:00:00Z"));
    cache.setQuery("new@1.0.0", [], now);
    await cache.save(now);
    const saved = JSON.parse(await readFile(join(dir, "osv-cache.json"), "utf8")) as {
      queries: object;
    };
    expect(Object.keys(saved.queries)).toEqual(["new@1.0.0"]);
  });

  it("never writes for an empty (--no-cache) cache", async () => {
    const cache = AdvisoryCache.empty();
    cache.setQuery("a@1.0.0", [], now);
    expect(await cache.save(now)).toBe(true);
  });

  it("reports a failed save instead of throwing", async () => {
    const blocker = join(dir, "file");
    await writeFile(blocker, "x");
    const cache = await AdvisoryCache.load(join(blocker, "nested"));
    cache.setQuery("a@1.0.0", [], now);
    expect(await cache.save(now)).toBe(false);
  });
});

describe("defaultCacheDir", () => {
  it("honours CHAINWATCH_CACHE_DIR", () => {
    expect(defaultCacheDir({ CHAINWATCH_CACHE_DIR: "/tmp/cw" })).toBe("/tmp/cw");
  });
});
