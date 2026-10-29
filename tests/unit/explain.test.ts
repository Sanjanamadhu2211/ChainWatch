import { describe, expect, it } from "vitest";
import { parsePackageSpec } from "../../src/cli/commands/explain";
import { ChainwatchError } from "../../src/core/errors";

describe("parsePackageSpec", () => {
  it.each([
    ["minimist", { name: "minimist", version: undefined }],
    ["minimist@0.0.8", { name: "minimist", version: "0.0.8" }],
    ["@scope/pkg", { name: "@scope/pkg", version: undefined }],
    ["@scope/pkg@1.2.3", { name: "@scope/pkg", version: "1.2.3" }],
  ])("parses %s", (spec, expected) => {
    expect(parsePackageSpec(spec)).toEqual(expected);
  });

  it.each(["", "@", "@1.2.3", "minimist@"])("rejects %j with exit code 2", (spec) => {
    let caught: unknown;
    try {
      parsePackageSpec(spec);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(ChainwatchError);
    expect((caught as ChainwatchError).exitCode).toBe(2);
  });
});
