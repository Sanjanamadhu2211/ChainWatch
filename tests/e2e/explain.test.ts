import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import { buildCli, fixture, runCli, startFakeOsv } from "./helpers";

type Fake = Awaited<ReturnType<typeof startFakeOsv>>;
let fake: Fake | undefined;
afterEach(() => fake?.server.close());

const env = async (url: string) => ({
  CHAINWATCH_OSV_URL: url,
  CHAINWATCH_CACHE_DIR: await mkdtemp(join(tmpdir(), "chainwatch-e2e-")),
});

describe("chainwatch explain", () => {
  beforeAll(buildCli, 60_000);

  it("explains every finding for name@version and nothing for other packages", async () => {
    fake = await startFakeOsv();
    const r = await runCli(
      ["explain", "minimist@0.0.8", fixture("vulnerable")],
      await env(fake.url),
    );
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("GHSA-xvch-5gv4-984h (CVE-2021-44906)");
    expect(r.stdout).toContain("GHSA-vh95-rmgr-6w4m");
    expect(r.stdout).toContain("Why it is prioritized:");
    expect(r.stdout).toContain("vulnerable-app -> mkdirp@0.5.1 -> minimist@0.0.8");
    expect(r.stdout).not.toContain("lodash");
  });

  it("accepts a bare name and matches every installed version", async () => {
    fake = await startFakeOsv();
    const r = await runCli(["explain", "lodash", fixture("vulnerable")], await env(fake.url));
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("lodash@4.17.15");
    expect(r.stdout.match(/^Advisory: /gm)?.length).toBeGreaterThan(1);
    expect(r.stdout).not.toContain("minimist@");
  });

  it("prints a no-match message for a clean package", async () => {
    fake = await startFakeOsv();
    const r = await runCli(["explain", "mkdirp@0.5.1", fixture("vulnerable")], await env(fake.url));
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("No known vulnerabilities found for mkdirp@0.5.1.");
  });

  it("exits 2 for an invalid package spec", async () => {
    fake = await startFakeOsv();
    const r = await runCli(["explain", "@", fixture("vulnerable")], await env(fake.url));
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("chainwatch: Invalid package");
    expect(fake.requests).toHaveLength(0);
  });

  it("exits 3 and says the result is not clean when OSV is unavailable", async () => {
    fake = await startFakeOsv({ status: 400 });
    const r = await runCli(["explain", "minimist", fixture("vulnerable")], await env(fake.url));
    expect(r.code).toBe(3);
    expect(r.stdout).toContain("NOT a clean result");
    expect(r.stdout).toContain(
      "No known vulnerabilities found for minimist in the packages that were checked.",
    );
    expect(r.stdout).not.toContain("No known vulnerabilities found for minimist.");
  });
});
