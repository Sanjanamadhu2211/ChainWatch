import { describe, expect, it } from "vitest";
import { fixedVersionsFor, inRange } from "../../src/advisories/matching";
import type { Advisory, AffectedRange } from "../../src/core/types";

const semverRange = (...events: AffectedRange["events"]): AffectedRange => ({
  type: "SEMVER",
  events,
});

describe("inRange", () => {
  const r = semverRange({ introduced: "0" }, { fixed: "4.17.21" });

  it("treats introduced 0 as the first version and fixed as exclusive", () => {
    expect(inRange(r, "0.0.1")).toBe(true);
    expect(inRange(r, "4.17.20")).toBe(true);
    expect(inRange(r, "4.17.21")).toBe(false);
    expect(inRange(r, "5.0.0")).toBe(false);
  });

  it("handles several introduced/fixed windows", () => {
    const multi = semverRange(
      { introduced: "1.0.0" },
      { fixed: "1.2.0" },
      { introduced: "2.0.0" },
      { fixed: "2.1.0" },
    );
    const versions = ["0.9.0", "1.1.0", "1.2.0", "1.9.9", "2.0.5", "2.1.0"];
    expect(versions.map((v) => inRange(multi, v))).toEqual([
      false,
      true,
      false,
      false,
      true,
      false,
    ]);
  });

  it("treats last_affected as inclusive", () => {
    const last = semverRange({ introduced: "1.0.0" }, { last_affected: "1.4.0" });
    expect(inRange(last, "1.4.0")).toBe(true);
    expect(inRange(last, "1.4.1")).toBe(false);
  });

  it("stays affected forever when there is no fix", () => {
    expect(inRange(semverRange({ introduced: "3.0.0" }), "99.0.0")).toBe(true);
  });

  it("does not guess for GIT ranges or non-semver versions", () => {
    expect(inRange({ type: "GIT", events: [{ introduced: "0" }] }, "1.0.0")).toBeUndefined();
    expect(inRange(r, "not-a-version")).toBeUndefined();
  });

  it("orders events by version, not by position in the list", () => {
    const shuffled = semverRange({ fixed: "1.2.0" }, { introduced: "1.0.0" });
    expect(inRange(shuffled, "1.1.0")).toBe(true);
  });
});

const advisory = (affected: Advisory["affected"]): Advisory => ({
  id: "GHSA-test",
  aliases: [],
  severity: { cvssVectors: [] },
  affected,
  references: [],
});

describe("fixedVersionsFor", () => {
  const entry = (packageName: string, ...events: AffectedRange["events"]) => ({
    packageName,
    versions: [],
    ranges: [semverRange(...events)],
  });

  it("returns the fix above the installed version", () => {
    const a = advisory([entry("lodash", { introduced: "0" }, { fixed: "4.17.21" })]);
    expect(fixedVersionsFor(a, "lodash", "4.17.15")).toEqual(["4.17.21"]);
  });

  it("only uses ranges that actually contain the installed version", () => {
    const a = advisory([
      {
        packageName: "x",
        versions: [],
        ranges: [
          semverRange({ introduced: "1.0.0" }, { fixed: "1.5.0" }),
          semverRange({ introduced: "2.0.0" }, { fixed: "2.3.0" }),
        ],
      },
    ]);
    expect(fixedVersionsFor(a, "x", "2.1.0")).toEqual(["2.3.0"]);
  });

  it("ignores other packages in the same record", () => {
    const a = advisory([
      entry("lodash", { introduced: "0" }, { fixed: "4.17.21" }),
      entry("lodash-es", { introduced: "0" }, { fixed: "9.9.9" }),
    ]);
    expect(fixedVersionsFor(a, "lodash", "4.0.0")).toEqual(["4.17.21"]);
  });

  it("returns nothing when no fix exists or the version is not affected", () => {
    expect(fixedVersionsFor(advisory([entry("x", { introduced: "0" })]), "x", "1.0.0")).toEqual([]);
    const fixedAlready = advisory([entry("x", { introduced: "0" }, { fixed: "1.0.0" })]);
    expect(fixedVersionsFor(fixedAlready, "x", "1.0.0")).toEqual([]);
  });
});
