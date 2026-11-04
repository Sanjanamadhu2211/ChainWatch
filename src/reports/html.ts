import type { Finding, ScanResult } from "../core/types";
import {
  advisoryDataText,
  aliasText,
  coverageText,
  fixedText,
  morePathsText,
  noFindingsText,
  policyLines,
  printable,
  problemLines,
  riskTag,
} from "./text";

const ENTITY: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

/** Every piece of scan text goes through here. Scripts never run: there are none and CSP forbids them. */
function esc(text: string): string {
  return printable(text).replace(/[&<>"']/g, (c) => ENTITY[c] ?? c);
}

/** Only https links become anchors; anything else (javascript:, data:, http:) is shown as plain text. */
function reference(ref: string): string {
  let url: URL;
  try {
    url = new URL(ref);
  } catch {
    return esc(ref);
  }
  return url.protocol === "https:"
    ? `<a href="${esc(url.href)}" rel="noopener noreferrer">${esc(ref)}</a>`
    : esc(ref);
}

function renderFinding(f: Finding): string {
  const path = f.dependencyPaths[0];
  const refs = f.references.length
    ? `<details class="references"><summary>Advisory references (${f.references.length})</summary><ul class="refs">${f.references.map((r) => `<li>${reference(r)}</li>`).join("")}</ul></details>`
    : "";
  return [
    `<article class="finding ${esc(f.riskLevel)}">`,
    `<div class="finding-header"><div><p class="advisory">${esc(f.advisoryId)}${esc(aliasText(f))}</p><h3>${esc(f.package.name)}<span class="version">@${esc(f.package.version)}</span></h3></div><span class="risk">${esc(riskTag(f))}</span></div>`,
    f.summary ? `<p class="finding-summary">${esc(f.summary)}</p>` : "",
    path
      ? `<p class="finding-path"><strong>Dependency path</strong><code>${esc(path.join(" → "))}</code>${esc(morePathsText(f))}</p>`
      : "",
    `<div class="remediation"><p><strong>Fixed in</strong> ${esc(fixedText(f))}</p><p><strong>Recommended action</strong> ${esc(f.suggestedAction)}</p></div>`,
    refs,
    "</article>",
  ].join("\n");
}

export function renderHtml(result: ScanResult): string {
  const levels = ["critical", "high", "medium", "low", "unknown"] as const;
  const counts = Object.fromEntries(levels.map((level) => [level, 0]));
  for (const finding of result.findings) counts[finding.riskLevel]!++;
  const breakdown = levels
    .map(
      (level) =>
        `<div class="metric ${level}"><span>${level[0]!.toUpperCase() + level.slice(1)}</span> <strong>${counts[level]}</strong></div>`,
    )
    .join("\n");
  const findings =
    result.findings.length === 0
      ? `<div class="empty">${esc(noFindingsText(result))}</div>`
      : result.findings.map(renderFinding).join("\n");
  const policy = policyLines(result);
  const problems = problemLines(result);
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ChainWatch scan report</title>
<style>
:root { color-scheme: light dark; --bg: #f1f4fa; --surface: #fff; --text: #17233d; --muted: #596b85; --border: #dce4f0; --accent: #285bd6; --critical: #b02e48; --medium: #966000; --low: #14745c; --subtle: #f5f7fc; --shadow: 0 12px 32px rgb(30 52 92 / 5%); }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text); font: 1rem/1.6 system-ui, sans-serif; }
.topbar { background: #101e38; color: #f7faff; border-bottom: 3px solid #4d7cff; }
.topbar-inner, main, footer { width: min(100% - 2.5rem, 70rem); margin: auto; }
.topbar-inner { display: flex; align-items: center; gap: .75rem; padding: 1.15rem 0; font-size: 1.1rem; font-weight: 760; letter-spacing: -.03em; }
.brand-mark { display: inline-grid; place-items: center; width: 2.25rem; height: 2.25rem; border: 1px solid #789cff; border-radius: .65rem; background: #315fda; color: #fff; font-weight: 800; }
main { padding: 3rem 0 3.5rem; }
.eyebrow { margin: 0 0 .5rem; color: var(--accent); font-size: .72rem; font-weight: 800; text-transform: uppercase; letter-spacing: .14em; }
h1 { margin: 0; font-size: clamp(2.2rem, 4.5vw, 3.25rem); letter-spacing: -.055em; line-height: 1.1; }
h2 { margin: 0 0 1.2rem; font-size: 1.1rem; letter-spacing: -.025em; }
.intro { display: flex; justify-content: space-between; align-items: center; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }
.status { padding: .5rem .9rem; border: 1px solid var(--border); border-radius: .6rem; background: var(--surface); box-shadow: var(--shadow); font-size: .8rem; font-weight: 700; }
.status.partial, .status.failed { color: var(--critical); border-color: currentColor; }
.overview, .finding, .empty, .policy, .problems { background: var(--surface); border: 1px solid var(--border); border-radius: .9rem; box-shadow: var(--shadow); }
.overview { padding: 1.6rem; margin-bottom: 1rem; }
.coverage { color: var(--muted); margin: .2rem 0; font-size: .91rem; }
.metrics { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: .75rem; margin-top: 1.5rem; }
.metric { position: relative; padding: 1rem 1rem .85rem; background: var(--subtle); border: 1px solid var(--border); border-radius: .65rem; }
.metric::before { content: ""; display: block; width: 1.5rem; height: 3px; margin-bottom: .85rem; border-radius: 2px; background: var(--muted); }
.metric.critical::before, .metric.high::before { background: var(--critical); }
.metric.medium::before { background: var(--medium); }
.metric.low::before { background: var(--low); }
.metric span { display: block; color: var(--muted); font-size: .75rem; font-weight: 700; }
.metric strong { display: block; margin-top: .2rem; font-size: 1.8rem; line-height: 1.15; font-variant-numeric: tabular-nums; }
.metric.critical strong, .metric.high strong { color: var(--critical); }
.metric.medium strong { color: var(--medium); }
.metric.low strong { color: var(--low); }
.findings-section { margin-top: 2.75rem; }
.findings-section > h2 { font-size: 1.35rem; }
.findings-section > h2 span { color: var(--muted); font-size: .9rem; font-weight: 500; }
.finding { padding: 1.5rem; margin: 1rem 0; overflow-wrap: anywhere; }
.finding-header { display: flex; align-items: start; justify-content: space-between; flex-wrap: wrap; gap: .75rem; }
.advisory { margin: 0 0 .3rem; color: var(--muted); font-size: .75rem; font-weight: 700; letter-spacing: .02em; }
.finding h3 { margin: 0; font-size: 1.2rem; letter-spacing: -.02em; }
.version { color: var(--muted); font-weight: 500; }
.risk { padding: .32rem .65rem; border: 1px solid currentColor; border-radius: .4rem; color: var(--muted); font-size: .72rem; font-weight: 800; }
.finding.critical .risk, .finding.high .risk { color: var(--critical); }
.finding.medium .risk { color: var(--medium); }
.finding.low .risk { color: var(--low); }
.finding-summary { margin: .9rem 0; color: var(--muted); }
.finding-path { margin: 1rem 0; padding: .9rem 1rem; border-radius: .55rem; background: var(--subtle); font-size: .85rem; }
.finding-path strong, .remediation strong { display: block; margin-bottom: .2rem; color: var(--text); font-size: .72rem; letter-spacing: .04em; text-transform: uppercase; }
.finding-path code { display: block; overflow-wrap: anywhere; }
.remediation { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 2fr); gap: 1.5rem; margin-top: 1.2rem; }
.remediation p { margin: 0; font-size: .9rem; }
.references { margin-top: 1.25rem; padding-top: 1rem; border-top: 1px solid var(--border); color: var(--accent); font-size: .85rem; }
.references summary { cursor: pointer; font-weight: 700; }
.refs { padding-left: 1.25rem; margin: .7rem 0 0; }
a { color: var(--accent); text-underline-offset: .15em; }
a:focus-visible, summary:focus-visible { outline: 3px solid var(--accent); outline-offset: 3px; }
.empty, .policy, .problems { padding: 1rem 1.25rem; margin: 1rem 0; }
.policy p, .problems p { margin: .25rem 0; }
.problems { border-left: 4px solid var(--critical); }
footer { padding: 0 0 2rem; color: var(--muted); font-size: .8rem; overflow-wrap: anywhere; }
@media (max-width: 600px) { .topbar-inner, main, footer { width: calc(100% - 2rem); } main { padding-top: 2rem; } .overview, .finding { padding: 1.15rem; } .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); } .remediation { grid-template-columns: 1fr; gap: .9rem; } }
@media (prefers-color-scheme: dark) { :root { --bg: #0b1425; --surface: #14223a; --text: #edf3ff; --muted: #b2c2dc; --border: #2b405f; --accent: #a8c4ff; --critical: #ff9eae; --medium: #fbd17b; --low: #8de0c2; --subtle: #1b2d49; --shadow: 0 12px 32px rgb(0 0 0 / 14%); } .topbar { background: #0b1425; } }
@media print { :root { color-scheme: light; --bg: #fff; --surface: #fff; --text: #111; --muted: #444; --border: #aaa; --accent: #234da8; --critical: #8d1820; --medium: #704900; --low: #14644e; --subtle: #f5f5f5; --shadow: none; } .topbar { background: #fff; color: #111; } .finding { break-inside: avoid; } }
</style>
</head>
<body>
<header class="topbar"><div class="topbar-inner"><span class="brand-mark" aria-hidden="true">C</span>ChainWatch</div></header>
<main>
<div class="intro"><div><p class="eyebrow">Dependency security</p><h1>Scan report</h1></div><div class="status ${esc(result.status)}">Status: ${esc(result.status[0]!.toUpperCase() + result.status.slice(1))}</div></div>
${problems.length ? `<section class="problems">${problems.map((l) => `<p>${esc(l)}</p>`).join("")}</section>` : ""}
<section class="overview" aria-labelledby="overview-title"><h2 id="overview-title">Scan overview</h2>
<p class="coverage">${esc(coverageText(result))}.</p><p class="coverage">${esc(advisoryDataText(result))}.</p>
<div class="metrics" aria-label="Findings by risk level">${breakdown}</div></section>
${policy.length ? `<section class="policy" aria-label="Policy result">${policy.map((l) => `<p>${esc(l)}</p>`).join("")}</section>` : ""}
<section class="findings-section" aria-labelledby="findings-title"><h2 id="findings-title">Findings <span>(${result.findings.length})</span></h2>${findings}</section>
</main>
<footer><p>Scan ${esc(result.scanId)} of ${esc(result.rootPath)} at ${esc(result.completedAt)} &middot; ChainWatch ${esc(result.toolVersion)}</p></footer>
</body>
</html>
`;
}
