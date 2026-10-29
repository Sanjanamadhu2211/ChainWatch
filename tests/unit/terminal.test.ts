import { describe, expect, it } from "vitest";
import { renderExplain, renderTerminal } from "../../src/reports/terminal";
import { finding, result } from "../helpers/result";

describe("renderTerminal", () => {
  it("shows the risk level and score on each finding line", () => {
    const out = renderTerminal(result({ findings: [finding()] }));
    expect(out).toContain("1 finding(s):");
    expect(out).toContain(
      "HIGH (score 87.9)  minimist@0.0.8  GHSA-xvch-5gv4-984h (CVE-2021-44906)",
    );
  });

  it("marks a finding without severity data as unknown", () => {
    const out = renderTerminal(
      result({ findings: [finding({ riskScore: null, riskLevel: "unknown" })] }),
    );
    expect(out).toContain("UNKNOWN (no score)  minimist@0.0.8");
  });

  it("says the scan is not clean when status is not complete", () => {
    const out = renderTerminal(
      result({
        status: "partial",
        errors: [{ code: "OSV_FAILED", message: "lookup failed" }],
      }),
    );
    expect(out).toContain("error [OSV_FAILED]: lookup failed");
    expect(out).toContain("The scan is partial: this is NOT a clean result.");
    expect(out).not.toContain("No known vulnerabilities found.");
  });

  it("escapes control characters so advisory text cannot rewrite the terminal", () => {
    const out = renderTerminal(result({ findings: [finding({ summary: "bad\u001b[2J\nline" })] }));
    expect(out).toContain("bad\\u001b[2J\\u000aline");
    expect(out).not.toContain("\u001b");
  });
});

describe("renderTerminal policy", () => {
  const policy = {
    passed: false,
    failOn: "high" as const,
    failingFindingIds: ["f1"],
    ignoredFindingIds: [],
    warnings: [],
  };

  it("states the policy decision and how many findings fail it", () => {
    const out = renderTerminal(result({ findings: [finding()], policy }));
    expect(out).toContain("Policy: failed at fail-on high; 1 finding(s) fail the policy.");
  });

  it("counts findings ignored by exceptions and prints warnings", () => {
    const out = renderTerminal(
      result({
        policy: {
          ...policy,
          passed: true,
          failingFindingIds: [],
          ignoredFindingIds: ["f1", "f2"],
          warnings: ["exception for CVE-1 expired on 2026-01-01; its findings count again"],
        },
      }),
    );
    expect(out).toContain("Policy: passed at fail-on high; 0 finding(s) fail the policy.");
    expect(out).toContain("2 finding(s) ignored by exceptions in the config.");
    expect(out).toContain(
      "warning: exception for CVE-1 expired on 2026-01-01; its findings count again",
    );
  });

  it("says the policy is not gating when fail-on is none", () => {
    const out = renderTerminal(result({ policy: { ...policy, failOn: "none", passed: true } }));
    expect(out).toContain("Policy: not gating (fail-on is none).");
    expect(out).not.toContain("fail the policy");
  });

  it("prints no policy line for a saved scan without a policy", () => {
    expect(renderTerminal(result())).not.toContain("Policy:");
  });
});

describe("renderExplain", () => {
  it("prints the detailed sections for a matching finding", () => {
    const out = renderExplain(result(), [finding()], "minimist@0.0.8");
    expect(out).toContain("HIGH (score 87.9) - minimist@0.0.8");
    expect(out).toContain("Advisory: GHSA-xvch-5gv4-984h (CVE-2021-44906)");
    expect(out).toContain("Why it is prioritized:");
    expect(out).toContain("  + Advisory severity: CVSS v3 base score 9.8 (contributes 78.4)");
    expect(out).toContain("Dependency path (1 of 1):");
    expect(out).toContain("  vulnerable-app -> mkdirp@0.5.1 -> minimist@0.0.8");
    expect(out).toContain("Recommended action:\n  Upgrade minimist to >=0.2.4");
    expect(out).toContain("Limitations:\n  Runtime reachability has not been evaluated.");
  });

  it("prints a no-match message for a clean complete scan", () => {
    const out = renderExplain(result(), [], "lodash");
    expect(out).toBe("No known vulnerabilities found for lodash.");
  });

  it("qualifies the no-match message when the scan was not complete", () => {
    const out = renderExplain(result({ status: "failed" }), [], "lodash");
    expect(out).toContain(
      "No known vulnerabilities found for lodash in the packages that were checked.",
    );
    expect(out).toContain("The scan is failed: this is NOT a clean result.");
  });

  it("separates several matching findings with a blank line", () => {
    const out = renderExplain(
      result(),
      [finding(), finding({ advisoryId: "GHSA-vh95-rmgr-6w4m" })],
      "minimist",
    );
    expect(out).toContain("GHSA-xvch-5gv4-984h");
    expect(out).toContain("\n\nHIGH (score 87.9) - minimist@0.0.8\nAdvisory: GHSA-vh95-rmgr-6w4m");
  });
});
