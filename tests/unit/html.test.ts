import { describe, expect, it } from "vitest";
import { renderHtml } from "../../src/reports/html";
import { renderJson } from "../../src/reports/json";
import { finding, result } from "../helpers/result";

const hostile = `<script>alert(1)</script>"'><img src=x onerror=alert(2)>\u001b[31m`;

describe("renderHtml", () => {
  it("escapes every piece of scan text", () => {
    const html = renderHtml(
      result({
        findings: [
          finding({
            summary: hostile,
            aliases: [hostile],
            suggestedAction: hostile,
            dependencyPaths: [["app", hostile]],
          }),
        ],
      }),
    );
    expect(html).not.toContain("<script>alert");
    expect(html).not.toContain("<img src=x");
    expect(html).not.toContain("\u001b");
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(html).toContain("\\u001b");
  });

  it("never emits a script element or inline event handler", () => {
    const html = renderHtml(result({ findings: [finding({ summary: hostile })] }));
    expect(html).not.toMatch(/<script/i);
    expect(html).not.toMatch(/<[a-z][^>]*\son\w+=/i);
  });

  it("keeps a strict content security policy", () => {
    const html = renderHtml(result());
    expect(html).toContain(`content="default-src 'none'; style-src 'unsafe-inline'"`);
  });

  it("links only https references", () => {
    const html = renderHtml(
      result({
        findings: [
          finding({
            references: [
              "https://github.com/advisories/GHSA-xvch-5gv4-984h",
              "javascript:alert(1)",
              "http://example.com/plain",
              `https://example.com/"onmouseover="x`,
            ],
          }),
        ],
      }),
    );
    expect(html).toContain(`<a href="https://github.com/advisories/GHSA-xvch-5gv4-984h"`);
    expect(html).not.toContain(`href="javascript:`);
    expect(html).not.toContain(`href="http://`);
    expect(html).not.toMatch(/onmouseover="x/);
  });

  it("states that a non-complete scan is not a clean result", () => {
    const html = renderHtml(result({ status: "partial" }));
    expect(html).toContain("NOT a clean result");
  });

  it("shows the policy decision with its warnings, escaped", () => {
    const html = renderHtml(
      result({
        policy: {
          passed: true,
          failOn: "critical",
          failingFindingIds: [],
          ignoredFindingIds: ["f1"],
          warnings: [hostile],
        },
      }),
    );
    expect(html).toContain("Policy: passed at fail-on critical; 0 finding(s) fail the policy.");
    expect(html).toContain("1 finding(s) ignored by exceptions in the config.");
    expect(html).not.toContain("<script>alert");
    expect(html).toContain("warning: &lt;script&gt;alert(1)");
  });

  it("omits the policy section for a saved scan without a policy", () => {
    expect(renderHtml(result())).not.toContain(`class="policy"`);
  });
});

describe("renderJson", () => {
  it("writes the full result as pretty JSON with a trailing newline", () => {
    const r = result({ findings: [finding()] });
    const out = renderJson(r);
    expect(out.endsWith("\n")).toBe(true);
    expect(JSON.parse(out)).toEqual(r);
  });
});
