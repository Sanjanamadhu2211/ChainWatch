import type { Advisory, Finding } from "../core/types";

const AV: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC: Record<string, number> = { L: 0.77, H: 0.44 };
const UI: Record<string, number> = { N: 0.85, R: 0.62 };
const CIA: Record<string, number> = { H: 0.56, L: 0.22, N: 0 };
// Privileged-required weights depend on whether the scope changes.
const PR_UNCHANGED: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
const PR_CHANGED: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 };

/** CVSS v3.1 "Roundup": smallest number with one decimal that is >= the input, safe from float noise. */
function roundUp(x: number): number {
  const n = Math.round(x * 100000);
  return n % 10000 === 0 ? n / 100000 : (Math.floor(n / 10000) + 1) / 10;
}

/**
 * Base score (0 to 10) of a CVSS v3.0 or v3.1 vector, or undefined if the vector is not a
 * complete, valid v3 vector. CVSS v4 and v2 are not supported.
 */
export function cvssV3BaseScore(vector: string): number | undefined {
  const parts = vector.split("/");
  if (parts[0] !== "CVSS:3.0" && parts[0] !== "CVSS:3.1") return undefined;
  const m = new Map<string, string>();
  for (const part of parts.slice(1)) {
    const [k, v] = part.split(":");
    if (!k || !v || m.has(k)) return undefined;
    m.set(k, v);
  }

  const scope = m.get("S");
  const changed = scope === "C";
  const av = AV[m.get("AV") ?? ""];
  const ac = AC[m.get("AC") ?? ""];
  const pr = (changed ? PR_CHANGED : PR_UNCHANGED)[m.get("PR") ?? ""];
  const ui = UI[m.get("UI") ?? ""];
  const c = CIA[m.get("C") ?? ""];
  const i = CIA[m.get("I") ?? ""];
  const a = CIA[m.get("A") ?? ""];
  if ((scope !== "U" && scope !== "C") || [av, ac, pr, ui, c, i, a].some((x) => x === undefined)) {
    return undefined;
  }

  const iss = 1 - (1 - (c as number)) * (1 - (i as number)) * (1 - (a as number));
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * (av as number) * (ac as number) * (pr as number) * (ui as number);
  const raw = changed ? 1.08 * (impact + exploitability) : impact + exploitability;
  return roundUp(Math.min(raw, 10));
}

const LABEL_RANK: Record<string, number> = { LOW: 1, MODERATE: 2, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

/**
 * Upstream severity for one vulnerability, which may be known under several advisory records:
 * the highest CVSS v3 score if any vector is usable, else the most severe known label, else none.
 */
export function normalizeSeverity(advisories: Advisory[]): Finding["upstreamSeverity"] {
  const scores = advisories
    .flatMap((a) => a.severity.cvssVectors)
    .map((v) => cvssV3BaseScore(v.vector))
    .filter((s): s is number => s !== undefined);
  const labels = advisories
    .map((a) => a.severity.label)
    .filter((l): l is string => l !== undefined && Object.hasOwn(LABEL_RANK, l))
    .sort((x, y) => (LABEL_RANK[y] as number) - (LABEL_RANK[x] as number));
  const label = labels[0];

  if (scores.length > 0) {
    return { cvssScore: Math.max(...scores), ...(label ? { label } : {}), source: "cvss-vector" };
  }
  return label ? { label, source: "label" } : { source: "none" };
}
