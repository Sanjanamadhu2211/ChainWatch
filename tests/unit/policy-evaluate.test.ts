import { describe, expect, it } from "vitest";
import { evaluatePolicy, type FailOn } from "../../src/policy/evaluate";
import type { Config } from "../../src/policy/config";
import { finding } from "../helpers/result";

const NOW = new Date("2026-06-10T12:00:00Z");
const policy = (overrides: Partial<Config["policy"]> = {}): Config["policy"] => ({
  failOn: "high",
  unknownSeverity: "report",
  ignore: [],
  ...overrides,
});
const evaluate = (findings: ReturnType<typeof finding>[], failOn: FailOn, p = policy()) =>
  evaluatePolicy(findings, p, { failOn, now: NOW });

describe("evaluatePolicy thresholds", () => {
  const high = finding({ id: "h", riskLevel: "high" });
  const medium = finding({ id: "m", riskLevel: "medium" });
  const critical = finding({ id: "c", riskLevel: "critical" });

  it("fails a high finding at fail-on high but passes a medium one", () => {
    const r = evaluate([high, medium], "high");
    expect(r.passed).toBe(false);
    expect(r.failingFindingIds).toEqual(["h"]);
  });

  it("passes medium findings at fail-on critical and fails critical ones", () => {
    expect(evaluate([high, medium], "critical").passed).toBe(true);
    expect(evaluate([critical], "critical").failingFindingIds).toEqual(["c"]);
  });

  it("never fails when fail-on is none", () => {
    const r = evaluate([critical, high], "none");
    expect(r.passed).toBe(true);
    expect(r.failingFindingIds).toEqual([]);
    expect(r.failOn).toBe("none");
  });

  it("follows unknownSeverity for findings without a score", () => {
    const unknown = finding({ id: "u", riskScore: null, riskLevel: "unknown" });
    expect(evaluate([unknown], "low").passed).toBe(true);
    const r = evaluate([unknown], "low", policy({ unknownSeverity: "fail" }));
    expect(r.passed).toBe(false);
    expect(r.failingFindingIds).toEqual(["u"]);
  });
});

describe("evaluatePolicy exceptions", () => {
  const f = finding({ id: "f1", advisoryId: "GHSA-xvch-5gv4-984h", aliases: ["CVE-2021-44906"] });

  it("ignores a finding excepted by advisory id", () => {
    const r = evaluate(
      [f],
      "high",
      policy({
        ignore: [{ advisoryId: "GHSA-xvch-5gv4-984h", reason: "tracked", expires: "2026-12-31" }],
      }),
    );
    expect(r.passed).toBe(true);
    expect(r.ignoredFindingIds).toEqual(["f1"]);
    expect(r.warnings).toEqual([]);
  });

  it("ignores a finding excepted by an alias", () => {
    const r = evaluate(
      [f],
      "high",
      policy({
        ignore: [{ advisoryId: "CVE-2021-44906", reason: "tracked", expires: "2026-12-31" }],
      }),
    );
    expect(r.passed).toBe(true);
    expect(r.ignoredFindingIds).toEqual(["f1"]);
  });

  it("keeps an exception active on its expiry day", () => {
    const r = evaluate(
      [f],
      "high",
      policy({
        ignore: [{ advisoryId: "CVE-2021-44906", reason: "tracked", expires: "2026-06-10" }],
      }),
    );
    expect(r.passed).toBe(true);
    expect(r.warnings).toEqual([]);
  });

  it("counts an expired exception again and warns", () => {
    const r = evaluate(
      [f],
      "high",
      policy({
        ignore: [{ advisoryId: "CVE-2021-44906", reason: "tracked", expires: "2026-06-09" }],
      }),
    );
    expect(r.passed).toBe(false);
    expect(r.failingFindingIds).toEqual(["f1"]);
    expect(r.ignoredFindingIds).toEqual([]);
    expect(r.warnings).toEqual([
      "exception for CVE-2021-44906 expired on 2026-06-09; its findings count again",
    ]);
  });
});
