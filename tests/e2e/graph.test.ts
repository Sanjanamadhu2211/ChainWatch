import { beforeAll, describe, expect, it } from "vitest";
import { buildCli, fixture, runCli } from "./helpers";

describe("chainwatch graph", () => {
  beforeAll(buildCli, 60_000);

  it("prints the dependency tree with dev markers", () => {
    const r = runCli(["graph", fixture("dev-and-prod")]);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("is-odd@3.0.1 [dev]");
    expect(r.stdout).toContain("3 packages installed");
  });

  it("exits 2 when there is no lockfile", () => {
    const r = runCli(["graph", fixture("malformed")]);
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("No lockfile found");
  });

  it("exits 2 for an unknown command", () => {
    expect(runCli(["bogus"]).code).toBe(2);
  });

  it("prints the version", () => {
    const r = runCli(["--version"]);
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/^\d+\.\d+\.\d+/);
  });
});
