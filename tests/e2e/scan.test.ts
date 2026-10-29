import { mkdtemp, writeFile } from "node:fs/promises";
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

/** Writes a temporary config file and returns its path. */
const configFile = async (text: string) => {
  const path = join(await mkdtemp(join(tmpdir(), "chainwatch-cfg-")), "chainwatch.yaml");
  await writeFile(path, text);
  return path;
};

describe("chainwatch scan", () => {
  beforeAll(buildCli, 60_000);

  it("reports vulnerabilities with their dependency path and fix", async () => {
    fake = await startFakeOsv();
    const r = await runCli(["scan", fixture("vulnerable")], await env(fake.url));
    expect(r.code).toBe(1);
    expect(r.stdout).toContain("8 finding(s)");
    expect(r.stdout).toContain("Policy: failed at fail-on high; 6 finding(s) fail the policy.");
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
    expect(r.code).toBe(1);
    expect(r.stdout).toContain("8 finding(s)");
    expect(fake.requests).toHaveLength(requestsBefore);
  });

  it("exits 3 offline with an empty cache", async () => {
    fake = await startFakeOsv();
    const r = await runCli(["scan", fixture("vulnerable"), "--offline"], await env(fake.url));
    expect(r.code).toBe(3);
    expect(fake.requests).toHaveLength(0);
  });

  it("does not fail the policy when --fail-on none is given", async () => {
    fake = await startFakeOsv();
    const r = await runCli(
      ["scan", fixture("vulnerable"), "--fail-on", "none"],
      await env(fake.url),
    );
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("Policy: not gating (fail-on is none).");
  });

  it("exits 2 for an unknown --fail-on level", async () => {
    fake = await startFakeOsv();
    const r = await runCli(
      ["scan", fixture("vulnerable"), "--fail-on", "severe"],
      await env(fake.url),
    );
    expect(r.code).toBe(2);
  });

  it("passes when every failing advisory has an active exception", async () => {
    fake = await startFakeOsv();
    const failing = [
      "GHSA-xvch-5gv4-984h",
      "GHSA-r5fr-rjxr-66jc",
      "GHSA-p6mc-m468-83gw",
      "GHSA-35jh-r3h4-6jhm",
      "GHSA-f23m-r3pf-42rh",
      "GHSA-xxjr-mmjv-4gpg",
    ];
    const ignore = failing
      .map(
        (id) =>
          `  - advisoryId: ${id}\n    reason: accepted for this test\n    expires: 2999-12-31`,
      )
      .join("\n");
    const config = await configFile(`version: 1\npolicy:\n  ignore:\n${ignore}\n`);
    const r = await runCli(
      ["scan", fixture("vulnerable"), "--config", config],
      await env(fake.url),
    );
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("6 finding(s) ignored by exceptions in the config.");
  });

  it("counts an expired exception again and says so", async () => {
    fake = await startFakeOsv();
    const config = await configFile(
      "version: 1\npolicy:\n  ignore:\n" +
        "  - advisoryId: CVE-2021-44906\n    reason: old acceptance\n    expires: 2020-01-01\n",
    );
    const r = await runCli(
      ["scan", fixture("vulnerable"), "--config", config],
      await env(fake.url),
    );
    expect(r.code).toBe(1);
    expect(r.stdout).toContain("exception for CVE-2021-44906 expired on 2020-01-01");
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
