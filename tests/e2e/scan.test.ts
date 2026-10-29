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

describe("chainwatch scan", () => {
  beforeAll(buildCli, 60_000);

  it("reports vulnerabilities with their dependency path and fix", async () => {
    fake = await startFakeOsv();
    const r = await runCli(["scan", fixture("vulnerable")], await env(fake.url));
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("8 finding(s)");
    expect(r.stdout).toContain("GHSA-35jh-r3h4-6jhm (CVE-2021-23337)");
    expect(r.stdout).toContain("vulnerable-app -> mkdirp@0.5.1 -> minimist@0.0.8");
    expect(r.stdout).toContain("Fixed in: 4.17.21");
  });

  it("exits 3 and says the result is not clean when OSV is unavailable", async () => {
    fake = await startFakeOsv({ status: 400 });
    const r = await runCli(["scan", fixture("vulnerable")], await env(fake.url));
    expect(r.code).toBe(3);
    expect(r.stdout).toContain("NOT a clean result");
    expect(r.stdout).not.toContain("No known vulnerabilities");
  });

  it("scans offline from the cache populated by an earlier run", async () => {
    fake = await startFakeOsv();
    const e = await env(fake.url);
    await runCli(["scan", fixture("vulnerable")], e);
    const requestsBefore = fake.requests.length;

    const r = await runCli(["scan", fixture("vulnerable"), "--offline"], e);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("8 finding(s)");
    expect(fake.requests).toHaveLength(requestsBefore);
  });

  it("exits 3 offline with an empty cache", async () => {
    fake = await startFakeOsv();
    const r = await runCli(["scan", fixture("vulnerable"), "--offline"], await env(fake.url));
    expect(r.code).toBe(3);
    expect(fake.requests).toHaveLength(0);
  });

  it("exits 2 for an invalid configuration", async () => {
    fake = await startFakeOsv();
    const r = await runCli(
      ["scan", fixture("vulnerable"), "--config", join(fixture("malformed"), "not-json.json")],
      await env(fake.url),
    );
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("chainwatch:");
  });
});
