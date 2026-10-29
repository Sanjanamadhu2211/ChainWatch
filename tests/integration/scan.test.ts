import { mkdtemp, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { LockfileError } from "../../src/core/errors";
import { runScan } from "../../src/core/scan";
import type { Advisory, Finding } from "../../src/core/types";
import { FixtureProvider } from "../helpers/fixture-provider";

const fixture = (name: string) => join(__dirname, "..", "fixtures", name);
const tempDir = () => mkdtemp(join(tmpdir(), "chainwatch-scan-"));

const find = (findings: Finding[], id: string) => findings.find((f) => f.advisoryId === id);

describe("runScan", () => {
  it("finds known vulnerabilities, with fixes, aliases and the direct/transitive split", async () => {
    const result = await runScan({
      path: fixture("vulnerable"),
      provider: new FixtureProvider(),
      noCache: true,
    });
    expect(result.status).toBe("complete");
    expect(result.errors).toEqual([]);
    expect(result.coverage).toMatchObject({
      packagesScanned: 3,
      queried: 3,
      failed: 0,
      skipped: 0,
    });
    expect(result.findings.filter((f) => f.package.name === "lodash")).toHaveLength(6);

    const cmdInjection = find(result.findings, "GHSA-35jh-r3h4-6jhm");
    expect(cmdInjection).toMatchObject({
      aliases: ["CVE-2021-23337"],
      direct: true,
      fixedVersions: ["4.17.21"],
      suggestedAction: "Upgrade lodash to 4.17.21 or later.",
    });
    expect(cmdInjection?.dependencyPaths).toEqual([["vulnerable-app", "lodash@4.17.15"]]);

    const transitive = result.findings.filter((f) => f.package.name === "minimist");
    expect(transitive).toHaveLength(2);
    expect(transitive[0]).toMatchObject({
      direct: false,
      dependencyPaths: [["vulnerable-app", "mkdirp@0.5.1", "minimist@0.0.8"]],
      dependencyPathCount: 1,
    });
    expect(transitive[0]?.suggestedAction).toContain("Update mkdirp@0.5.1");
    expect(transitive[0]?.fixedVersions.length).toBeGreaterThan(0);
  });

  it("does not report the advisory a newer version already fixed", async () => {
    const result = await runScan({
      path: fixture("patched"),
      provider: new FixtureProvider(),
      noCache: true,
    });
    expect(find(result.findings, "GHSA-35jh-r3h4-6jhm")).toBeUndefined();
  });

  it("returns a complete, empty result for a package with no advisories", async () => {
    const result = await runScan({
      path: fixture("patched"),
      provider: new FixtureProvider({ ids: { "lodash@4.17.21": [] } }),
      noCache: true,
    });
    expect(result.findings).toEqual([]);
    expect(result.status).toBe("complete");
  });

  it("merges a GHSA and its CVE into one finding and drops withdrawn advisories", async () => {
    const base = { severity: { cvssVectors: [] }, affected: [], references: [] };
    const advisories: Advisory[] = [
      {
        ...base,
        id: "CVE-2099-1",
        aliases: [],
        summary: "from the CVE record",
        references: ["https://a"],
      },
      { ...base, id: "GHSA-aaaa-bbbb-cccc", aliases: ["CVE-2099-1"], references: ["https://b"] },
      { ...base, id: "GHSA-gone-gone-gone", aliases: [], withdrawn: "2024-01-01T00:00:00Z" },
    ];
    const result = await runScan({
      path: fixture("patched"),
      noCache: true,
      provider: new FixtureProvider({
        advisories,
        ids: { "lodash@4.17.21": advisories.map((a) => a.id) },
      }),
    });
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({
      advisoryId: "GHSA-aaaa-bbbb-cccc",
      aliases: ["CVE-2099-1"],
      summary: "from the CVE record",
      references: ["https://a", "https://b"],
    });
  });

  describe("failures", () => {
    it("never turns a failed lookup into a clean result", async () => {
      const result = await runScan({
        path: fixture("vulnerable"),
        provider: new FixtureProvider({ failAll: true }),
        noCache: true,
      });
      expect(result.status).toBe("failed");
      expect(result.findings).toEqual([]);
      expect(result.coverage.failed).toBe(3);
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0]).toMatchObject({ code: "ADVISORY_LOOKUP_FAILED" });
      expect(result.errors[0]?.message).toContain("3 package(s) could not be checked");
    });

    it("reports a partial scan and still returns what it found", async () => {
      const result = await runScan({
        path: fixture("vulnerable"),
        provider: new FixtureProvider({ failPackages: ["lodash@4.17.15"] }),
        noCache: true,
      });
      expect(result.status).toBe("partial");
      expect(result.coverage).toMatchObject({ queried: 3, failed: 1 });
      expect(result.findings.map((f) => f.package.name)).toEqual(["minimist", "minimist"]);
    });

    it("marks the package as failed when one of its advisories cannot be fetched", async () => {
      const result = await runScan({
        path: fixture("vulnerable"),
        provider: new FixtureProvider({ failAdvisories: ["GHSA-35jh-r3h4-6jhm"] }),
        noCache: true,
      });
      expect(result.status).toBe("partial");
      expect(result.errors[0]?.message).toContain("GHSA-35jh-r3h4-6jhm");
      expect(result.findings.filter((f) => f.package.name === "lodash")).toHaveLength(5);
    });

    it("rejects a project without a lockfile", async () => {
      await expect(
        runScan({ path: fixture("malformed"), provider: new FixtureProvider() }),
      ).rejects.toThrow(LockfileError);
    });
  });

  describe("coverage gaps", () => {
    it("warns about non-registry packages instead of treating them as clean", async () => {
      const result = await runScan({
        path: fixture("non-registry"),
        provider: new FixtureProvider(),
        noCache: true,
      });
      expect(result.status).toBe("complete");
      expect(result.coverage).toMatchObject({ queried: 1, skipped: 2 });
      expect(result.warnings.join("\n")).toContain("left-pad@1.3.0");
      expect(result.warnings.join("\n")).toContain("local-lib@0.1.0");
    });

    it("skips workspace members without warning about them", async () => {
      const result = await runScan({
        path: fixture("workspaces"),
        provider: new FixtureProvider(),
        noCache: true,
      });
      expect(result.coverage.skipped).toBe(2);
      expect(result.warnings).toEqual([]);
    });
  });

  describe("cache and offline mode", () => {
    const t0 = new Date("2026-06-01T12:00:00Z");
    const later = new Date(t0.getTime() + 2 * 60 * 60 * 1000); // past the 1h default TTL

    it("answers from the cache while it is fresh", async () => {
      const cacheDir = await tempDir();
      const provider = new FixtureProvider();
      await runScan({ path: fixture("vulnerable"), provider, cacheDir, now: () => t0 });
      expect(provider.queryCalls).toBe(1);

      const again = await runScan({
        path: fixture("vulnerable"),
        provider,
        cacheDir,
        now: () => t0,
      });
      expect(provider.queryCalls).toBe(1);
      expect(again.advisoryData).toMatchObject({ freshLookups: 0, staleCacheHits: 0 });
      expect(again.advisoryData.cacheHits).toBeGreaterThan(0);
      expect(again.findings).toHaveLength(8);
    });

    it("asks OSV again once the cache entries have expired", async () => {
      const cacheDir = await tempDir();
      const provider = new FixtureProvider();
      await runScan({ path: fixture("vulnerable"), provider, cacheDir, now: () => t0 });
      await runScan({ path: fixture("vulnerable"), provider, cacheDir, now: () => later });
      expect(provider.queryCalls).toBe(2);
    });

    it("uses stale entries offline and says so", async () => {
      const cacheDir = await tempDir();
      await runScan({
        path: fixture("vulnerable"),
        provider: new FixtureProvider(),
        cacheDir,
        now: () => t0,
      });

      const provider = new FixtureProvider();
      const offline = await runScan({
        path: fixture("vulnerable"),
        provider,
        cacheDir,
        offline: true,
        now: () => later,
      });
      expect(provider.queryCalls + provider.advisoryCalls).toBe(0);
      expect(offline.status).toBe("complete");
      expect(offline.findings).toHaveLength(8);
      expect(offline.advisoryData.staleCacheHits).toBeGreaterThan(0);
      expect(offline.advisoryData.oldestFetchedAt).toBe(t0.toISOString());
    });

    it("fails offline when nothing is cached, instead of reporting a clean scan", async () => {
      const provider = new FixtureProvider();
      const result = await runScan({
        path: fixture("vulnerable"),
        provider,
        cacheDir: await tempDir(),
        offline: true,
      });
      expect(provider.queryCalls).toBe(0);
      expect(result.status).toBe("failed");
      expect(result.errors[0]).toMatchObject({ code: "OFFLINE_CACHE_MISS" });
    });

    it("does not read or write the cache with noCache", async () => {
      const cacheDir = await tempDir();
      const provider = new FixtureProvider();
      await runScan({ path: fixture("vulnerable"), provider, cacheDir, noCache: true });
      await runScan({ path: fixture("vulnerable"), provider, cacheDir, noCache: true });
      expect(provider.queryCalls).toBe(2);
      expect(await readdir(cacheDir)).toEqual([]);
    });
  });
});
