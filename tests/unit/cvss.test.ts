import { describe, expect, it } from "vitest";
import { cvssV3BaseScore, normalizeSeverity } from "../../src/advisories/cvss";
import type { Advisory } from "../../src/core/types";

describe("cvssV3BaseScore", () => {
  // Reference values from the FIRST CVSS v3.1 specification and the NVD calculator.
  it.each([
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8],
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5],
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1],
    ["CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8],
    ["CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9],
    ["CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2],
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", 5.3],
    ["CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6],
    ["CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8],
  ])("%s scores %s", (vector, expected) => {
    expect(cvssV3BaseScore(vector)).toBe(expected);
  });

  it("scores 0 when there is no impact", () => {
    expect(cvssV3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")).toBe(0);
  });

  it("ignores temporal and environmental metrics appended to the base vector", () => {
    expect(cvssV3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C")).toBe(9.8);
  });

  it.each([
    ["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"],
    ["AV:N/AC:L/Au:N/C:P/I:P/A:P"],
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H"],
    ["CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"],
    ["CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"],
    ["not a vector"],
    [""],
  ])("returns undefined for %s", (vector) => {
    expect(cvssV3BaseScore(vector)).toBeUndefined();
  });
});

const advisory = (severity: Advisory["severity"]): Advisory => ({
  id: "X",
  aliases: [],
  severity,
  affected: [],
  references: [],
});

describe("normalizeSeverity", () => {
  const v98 = { type: "CVSS_V3", vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" };
  const v53 = { type: "CVSS_V3", vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L" };
  const v4 = {
    type: "CVSS_V4",
    vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
  };

  it("prefers a CVSS vector and keeps the label for display", () => {
    expect(normalizeSeverity([advisory({ cvssVectors: [v53], label: "MODERATE" })])).toEqual({
      cvssScore: 5.3,
      label: "MODERATE",
      source: "cvss-vector",
    });
  });

  it("takes the highest score across merged advisories", () => {
    const merged = [advisory({ cvssVectors: [v53] }), advisory({ cvssVectors: [v98] })];
    expect(normalizeSeverity(merged).cvssScore).toBe(9.8);
  });

  it("falls back to the label when only an unsupported vector exists", () => {
    expect(normalizeSeverity([advisory({ cvssVectors: [v4], label: "HIGH" })])).toEqual({
      label: "HIGH",
      source: "label",
    });
  });

  it("uses the most severe label across merged advisories", () => {
    const merged = [
      advisory({ cvssVectors: [], label: "LOW" }),
      advisory({ cvssVectors: [], label: "CRITICAL" }),
    ];
    expect(normalizeSeverity(merged)).toEqual({ label: "CRITICAL", source: "label" });
  });

  it("reports no severity rather than inventing one", () => {
    expect(normalizeSeverity([advisory({ cvssVectors: [v4] })])).toEqual({ source: "none" });
    expect(normalizeSeverity([advisory({ cvssVectors: [], label: "WHATEVER" })])).toEqual({
      source: "none",
    });
    expect(normalizeSeverity([advisory({ cvssVectors: [], label: "toString" })])).toEqual({
      source: "none",
    });
    expect(normalizeSeverity([])).toEqual({ source: "none" });
  });
});
