import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import { buildCli, fixture, runCli, startFakeOsv } from "./helpers";

type Fake = Awaited<ReturnType<typeof startFakeOsv>>;
let fake: Fake | undefined;
afterEach(() => fake?.server.close());

const dir = () => mkdtemp(join(tmpdir(), "chainwatch-report-"));
const env = async (url: string) => ({
  CHAINWATCH_OSV_URL: url,
  CHAINWATCH_CACHE_DIR: await dir(),
});

/** Scans a fixture into a scan.json file and returns the scan's exit result and file path. */
async function scanToJson(name: string, url: string) {
  const out = join(await dir(), "scan.json");
  const r = await runCli(
    ["scan", fixture(name), "--format", "json", "--output", out],
    await env(url),
  );
  return { r, out };
}

describe("chainwatch report", () => {
  beforeAll(buildCli, 60_000);

  it("renders a saved scan as HTML without looking up advisories again", async () => {
    fake = await startFakeOsv();
    const { r, out } = await scanToJson("vulnerable", fake.url);
    expect(r.code).toBe(0);
    expect(r.stdout).toBe("");
    expect(JSON.parse(await readFile(out, "utf8")).findings).toHaveLength(8);

    const before = fake.requests.length;
    const html = await runCli(["report", "--input", out, "--format", "html"], {
      CHAINWATCH_OSV_URL: fake.url,
    });
    expect(html.code).toBe(0);
    expect(html.stdout).toContain("8 finding(s)");
    expect(html.stdout).toContain("Fixed in: 4.17.21");
    expect(html.stdout).toContain("Content-Security-Policy");
    expect(fake.requests).toHaveLength(before);
  });

  it("prints the findings, path and fix in the terminal format by default", async () => {
    fake = await startFakeOsv();
    const { out } = await scanToJson("vulnerable", fake.url);
    const r = await runCli(["report", "--input", out]);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("GHSA-35jh-r3h4-6jhm (CVE-2021-23337)");
    expect(r.stdout).toContain("vulnerable-app -> mkdirp@0.5.1 -> minimist@0.0.8");
    expect(r.stdout).toContain("Fixed in: 4.17.21");
  });

  it("explains a package from a saved scan without scanning again", async () => {
    fake = await startFakeOsv();
    const { out } = await scanToJson("vulnerable", fake.url);
    const before = fake.requests.length;
    const r = await runCli(["explain", "minimist@0.0.8", "--input", out], {
      CHAINWATCH_OSV_URL: fake.url,
    });
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("GHSA-xvch-5gv4-984h (CVE-2021-44906)");
    expect(r.stdout).toContain("Why it is prioritized:");
    expect(fake.requests).toHaveLength(before);
  });

  it("drops the advisory that lodash 4.17.21 fixes and shows the newer fix versions", async () => {
    fake = await startFakeOsv();
    const { r, out } = await scanToJson("patched", fake.url);
    expect(r.code).toBe(0);
    const report = await runCli(["report", "--input", out]);
    expect(report.code).toBe(0);
    expect(report.stdout).not.toContain("GHSA-35jh-r3h4-6jhm");
    expect(report.stdout).toContain("lodash@4.17.21");
    expect(report.stdout).toContain("Fixed in: 4.18.0");
    expect(report.stdout).toContain("Action: Upgrade lodash to 4.18.0 or later.");
  });

  it("exits 3 and says the result is not clean when a saved scan is partial", async () => {
    fake = await startFakeOsv({ status: 400 });
    const { r, out } = await scanToJson("vulnerable", fake.url);
    expect(r.code).toBe(3);
    const report = await runCli(["report", "--input", out, "--format", "html"]);
    expect(report.code).toBe(3);
    expect(report.stdout).toContain("NOT a clean result");
  });

  it("exits 2 for a file that is not JSON", async () => {
    const file = join(await dir(), "scan.json");
    await writeFile(file, "{not json");
    const r = await runCli(["report", "--input", file]);
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("is not readable JSON");
  });

  it("exits 2 for JSON that is not a scan result", async () => {
    const file = join(await dir(), "scan.json");
    await writeFile(file, JSON.stringify({ findings: [], surprise: true }));
    const r = await runCli(["report", "--input", file]);
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("is not a chainwatch scan result");
  });

  it("exits 2 when the output file cannot be written", async () => {
    fake = await startFakeOsv();
    const { out } = await scanToJson("vulnerable", fake.url);
    const r = await runCli([
      "report",
      "--input",
      out,
      "--output",
      join(await dir(), "missing", "report.html"),
    ]);
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("Cannot write the report");
  });
});
