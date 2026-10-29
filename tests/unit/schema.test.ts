import { describe, expect, it } from "vitest";
import { parseOsvVuln } from "../../src/advisories/schema";
import { loadVuln } from "../helpers/fixture-provider";

describe("parseOsvVuln", () => {
  it("normalizes a real GHSA record", () => {
    const a = parseOsvVuln(loadVuln("GHSA-35jh-r3h4-6jhm"));
    expect(a.id).toBe("GHSA-35jh-r3h4-6jhm");
    expect(a.aliases).toContain("CVE-2021-23337");
    expect(a.severity.label).toBe("HIGH");
    expect(a.withdrawn).toBeUndefined();
    const lodash = a.affected.find((e) => e.packageName === "lodash");
    expect(lodash?.ranges[0]).toEqual({
      type: "SEMVER",
      events: [{ introduced: "0" }, { fixed: "4.17.21" }],
    });
    expect(a.references.length).toBeGreaterThan(0);
  });

  it("keeps only npm entries and known range types", () => {
    const a = parseOsvVuln({
      id: "X-1",
      affected: [
        {
          package: { name: "a", ecosystem: "PyPI" },
          ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }] }],
        },
        {
          package: { name: "b", ecosystem: "npm" },
          ranges: [
            { type: "WEIRD", events: [] },
            { type: "GIT", events: [{ introduced: "0" }] },
          ],
        },
      ],
    });
    expect(a.affected).toEqual([
      { packageName: "b", versions: [], ranges: [{ type: "GIT", events: [{ introduced: "0" }] }] },
    ]);
  });

  it("tolerates missing optional fields and records withdrawn advisories", () => {
    const a = parseOsvVuln({ id: "X-2", withdrawn: "2024-01-01T00:00:00Z" });
    expect(a).toMatchObject({
      aliases: [],
      affected: [],
      references: [],
      withdrawn: "2024-01-01T00:00:00Z",
    });
    expect(a.severity).toEqual({ cvssVectors: [] });
  });

  it("collects CVSS vectors and upper-cases the label", () => {
    const vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
    const a = parseOsvVuln({
      id: "X-3",
      severity: [{ type: "CVSS_V3", score: vector }],
      database_specific: { severity: "moderate" },
    });
    expect(a.severity.cvssVectors).toEqual([{ type: "CVSS_V3", vector }]);
    expect(a.severity.label).toBe("MODERATE");
  });

  it("rejects a record without an id", () => {
    expect(() => parseOsvVuln({ summary: "no id" })).toThrow();
  });
});
