import { describe, expect, it } from "vitest";
import { exitCodeFor } from "../../src/cli/commands/scan";
import type { PolicyResult } from "../../src/core/types";
import { result } from "../helpers/result";

const policy = (overrides: Partial<PolicyResult> = {}): PolicyResult => ({
  passed: true,
  failOn: "high",
  failingFindingIds: [],
  ignoredFindingIds: [],
  warnings: [],
  ...overrides,
});

describe("exitCodeFor", () => {
  it("returns 0 when the scan is complete and the policy passes", () => {
    expect(exitCodeFor(result({ policy: policy() }))).toBe(0);
  });

  it("returns 1 when the policy fails on a complete scan", () => {
    const failed = policy({ passed: false, failingFindingIds: ["f1"] });
    expect(exitCodeFor(result({ policy: failed }))).toBe(1);
  });

  it("returns 3 over a policy failure when the scan is partial", () => {
    const failed = policy({ passed: false, failingFindingIds: ["f1"] });
    expect(exitCodeFor(result({ status: "partial", policy: failed }))).toBe(3);
  });

  it("returns 3 for a failed scan even when the policy passes", () => {
    expect(exitCodeFor(result({ status: "failed", policy: policy() }))).toBe(3);
  });

  it("returns 0 for a complete scan without a policy result", () => {
    expect(exitCodeFor(result())).toBe(0);
  });
});
