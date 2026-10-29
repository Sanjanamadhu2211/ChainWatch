import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ConfigError } from "../../src/core/errors";
import { defaultConfig, loadConfig, parseConfig } from "../../src/policy/config";

describe("parseConfig", () => {
  it("fills in defaults for a minimal file", () => {
    const config = parseConfig("version: 1");
    expect(config).toEqual(defaultConfig());
    expect(config.policy).toMatchObject({ failOn: "high", unknownSeverity: "report", ignore: [] });
    expect(config.risk.weights).toEqual({ severity: 0.8, exposure: 0.2 });
  });

  it("accepts the shipped example file", () => {
    const text = readFileSync(join(__dirname, "..", "..", "chainwatch.example.yaml"), "utf8");
    expect(parseConfig(text).advisories.cacheTtlSeconds).toBe(3600);
  });

  it("rejects unknown keys instead of ignoring them", () => {
    expect(() => parseConfig("version: 1\npolicy:\n  falOn: high")).toThrow(/falOn/);
    expect(() => parseConfig("version: 1\nextra: true")).toThrow(ConfigError);
  });

  it("requires the version field", () => {
    expect(() => parseConfig("policy:\n  failOn: high")).toThrow(/version/);
  });

  it("requires weights that sum to one", () => {
    const text = "version: 1\nrisk:\n  weights:\n    severity: 0.9\n    exposure: 0.3";
    expect(() => parseConfig(text)).toThrow(/sum to 1/);
  });

  it("rejects negative weights", () => {
    const text = "version: 1\nrisk:\n  weights:\n    severity: 1.5\n    exposure: -0.5";
    expect(() => parseConfig(text)).toThrow(ConfigError);
  });

  describe("ignore entries", () => {
    const entry = (body: string) => `version: 1\npolicy:\n  ignore:\n    - ${body}`;

    it("accepts a complete exception", () => {
      const config = parseConfig(
        entry('{ advisoryId: GHSA-aaaa-bbbb-cccc, reason: "tracked", expires: "2026-12-31" }'),
      );
      expect(config.policy.ignore).toHaveLength(1);
    });

    it.each([
      ["a missing reason", '{ advisoryId: GHSA-aaaa-bbbb-cccc, expires: "2026-12-31" }'],
      ["a missing expiry", '{ advisoryId: GHSA-aaaa-bbbb-cccc, reason: "x" }'],
      ["a package-wide ignore", '{ package: lodash, reason: "x", expires: "2026-12-31" }'],
      ["a malformed date", '{ advisoryId: GHSA-a, reason: "x", expires: "12/31/2026" }'],
      ["an impossible date", '{ advisoryId: GHSA-a, reason: "x", expires: "2026-02-31" }'],
    ])("rejects %s", (_name, body) => {
      expect(() => parseConfig(entry(body))).toThrow(ConfigError);
    });
  });

  it("reports invalid YAML as a configuration error", () => {
    expect(() => parseConfig("version: [1")).toThrow(/not valid YAML/);
  });
});

describe("loadConfig", () => {
  const dir = join(__dirname, "..", "fixtures", "vulnerable");

  it("falls back to defaults when no file exists", async () => {
    expect(await loadConfig(dir)).toEqual(defaultConfig());
  });

  it("fails when an explicit config path does not exist", async () => {
    await expect(loadConfig(dir, join(dir, "nope.yaml"))).rejects.toThrow(ConfigError);
  });

  it("loads an explicit config file", async () => {
    const example = join(__dirname, "..", "..", "chainwatch.example.yaml");
    expect((await loadConfig(dir, example)).policy.failOn).toBe("high");
  });
});
