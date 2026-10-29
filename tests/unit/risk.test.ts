import { describe, expect, it } from "vitest";
import { rankFindings } from "../../src/risk/ranking";
import { riskLevelFor, scoreFinding, type RiskInput } from "../../src/risk/scoring";

const cvss = (cvssScore: number, extra: Partial<RiskInput> = {}): RiskInput => ({
  upstreamSeverity: { cvssScore, source: "cvss-vector" },
  dev: false,
  optional: false,
  ...extra,
});

describe("scoreFinding", () => {
  it("combines severity (80%) and runtime exposure (20%)", () => {
    const r = scoreFinding(cvss(7.5));
    expect(r.riskScore).toBe(80); // 0.8 * 75 + 0.2 * 100
    expect(r.riskLevel).toBe("high");
  });

  it("explains the score with factors that add up to it", () => {
    const r = scoreFinding(cvss(9.8));
    expect(r.factors.map((f) => f.name)).toEqual(["Advisory severity", "Runtime exposure"]);
    expect(r.factors[0]?.reason).toBe("CVSS v3 base score 9.8");
    expect(r.factors[1]?.reason).toBe("Production dependency");
    const sum = r.factors.reduce((s, f) => s + f.contribution, 0);
    expect(sum).toBeCloseTo(r.riskScore as number, 1);
  });

  it("scores dev-only and optional packages lower than production ones", () => {
    const prod = scoreFinding(cvss(7.5)).riskScore as number;
    const optional = scoreFinding(cvss(7.5, { optional: true })).riskScore as number;
    const dev = scoreFinding(cvss(7.5, { dev: true })).riskScore as number;
    expect(prod).toBeGreaterThan(optional);
    expect(optional).toBeGreaterThan(dev);
    expect(dev).toBe(68); // 0.8 * 75 + 0.2 * 40
    expect(scoreFinding(cvss(7.5, { dev: true })).factors[1]?.reason).toBe(
      "Development-only dependency",
    );
  });

  it("converts a severity label when there is no vector", () => {
    const r = scoreFinding({
      upstreamSeverity: { label: "MODERATE", source: "label" },
      dev: false,
      optional: false,
    });
    expect(r.riskScore).toBe(64); // 0.8 * 55 + 20
    expect(r.factors[0]?.reason).toContain("MODERATE");
  });

  it("returns null, not zero, when severity is unknown", () => {
    const r = scoreFinding({ upstreamSeverity: { source: "none" }, dev: false, optional: false });
    expect(r).toMatchObject({ riskScore: null, riskLevel: "unknown" });
    expect(r.factors[0]?.reason).toContain("no usable severity");
  });

  it("scores a CVSS 0 finding as a real, low score", () => {
    const r = scoreFinding(cvss(0));
    expect(r.riskScore).toBe(20);
    expect(r.riskLevel).toBe("low");
  });

  it("honours custom weights", () => {
    const r = scoreFinding(cvss(5), { severity: 1, exposure: 0 });
    expect(r.riskScore).toBe(50);
  });
});

describe("riskLevelFor", () => {
  it.each([
    [100, "critical"],
    [90, "critical"],
    [89.9, "high"],
    [70, "high"],
    [69.9, "medium"],
    [40, "medium"],
    [39.9, "low"],
    [0, "low"],
  ])("%s is %s", (score, level) => {
    expect(riskLevelFor(score)).toBe(level);
  });
});

describe("rankFindings", () => {
  const f = (name: string, version: string, advisoryId: string, riskScore: number | null) => ({
    package: { ecosystem: "npm" as const, name, version },
    advisoryId,
    riskScore,
  });

  it("orders by score, then name, version and advisory id, with unknowns last", () => {
    const ranked = rankFindings([
      f("b", "1.0.0", "GHSA-2", 50),
      f("z", "1.0.0", "GHSA-9", null),
      f("a", "1.0.0", "GHSA-1", 50),
      f("a", "1.0.0", "GHSA-0", 50),
      f("c", "1.0.0", "GHSA-3", 90),
      f("a", "1.0.0", "GHSA-8", null),
    ]);
    expect(ranked.map((x) => `${x.package.name}:${x.advisoryId}`)).toEqual([
      "c:GHSA-3",
      "a:GHSA-0",
      "a:GHSA-1",
      "b:GHSA-2",
      "a:GHSA-8",
      "z:GHSA-9",
    ]);
  });

  it("compares versions numerically and gives the same order for any input order", () => {
    const items = [f("a", "1.10.0", "G", 5), f("a", "1.2.0", "G", 5), f("a", "1.9.0", "G", 5)];
    const expected = ["1.2.0", "1.9.0", "1.10.0"];
    expect(rankFindings(items).map((x) => x.package.version)).toEqual(expected);
    expect(rankFindings([...items].reverse()).map((x) => x.package.version)).toEqual(expected);
  });

  it("does not modify its input", () => {
    const items = [f("b", "1", "G", 1), f("a", "1", "G", 2)];
    rankFindings(items);
    expect(items[0]?.package.name).toBe("b");
  });
});
