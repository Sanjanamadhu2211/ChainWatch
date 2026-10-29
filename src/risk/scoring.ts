import type { Finding, RiskFactor, RiskLevel } from "../core/types";

export interface RiskWeights {
  severity: number;
  exposure: number;
}

export const DEFAULT_WEIGHTS: RiskWeights = { severity: 0.8, exposure: 0.2 };

/** 0 to 100 severity values used when an advisory only carries a label, not a CVSS vector. */
export const LABEL_SEVERITY: Record<string, number> = {
  CRITICAL: 95,
  HIGH: 80,
  MODERATE: 55,
  MEDIUM: 55,
  LOW: 20,
};

// Initial thresholds; calibrate against fixtures and document in docs/risk-scoring.md.
export const LEVEL_THRESHOLDS = { critical: 90, high: 70, medium: 40 } as const;

export function riskLevelFor(score: number): Exclude<RiskLevel, "unknown"> {
  if (score >= LEVEL_THRESHOLDS.critical) return "critical";
  if (score >= LEVEL_THRESHOLDS.high) return "high";
  if (score >= LEVEL_THRESHOLDS.medium) return "medium";
  return "low";
}

export type RiskInput = Pick<Finding, "upstreamSeverity" | "dev" | "optional">;
export type RiskResult = Pick<Finding, "riskScore" | "riskLevel" | "factors">;

const round1 = (n: number) => Math.round(n * 10) / 10;

function severityValue(
  s: Finding["upstreamSeverity"],
): { value: number; reason: string } | undefined {
  if (s.source === "cvss-vector" && s.cvssScore !== undefined) {
    return { value: s.cvssScore * 10, reason: `CVSS v3 base score ${s.cvssScore.toFixed(1)}` };
  }
  const labelValue =
    s.label && Object.hasOwn(LABEL_SEVERITY, s.label) ? LABEL_SEVERITY[s.label] : undefined;
  if (s.source === "label" && s.label && labelValue !== undefined) {
    return {
      value: labelValue,
      reason: `Upstream severity label ${s.label} (no CVSS vector available)`,
    };
  }
  return undefined;
}

function exposure(input: RiskInput): { value: number; reason: string } {
  if (input.dev) return { value: 40, reason: "Development-only dependency" };
  if (input.optional) return { value: 60, reason: "Optional dependency" };
  return { value: 100, reason: "Production dependency" };
}

/**
 * risk = weights.severity * severity + weights.exposure * exposure, both on a 0 to 100 scale.
 * Without usable severity data the score is null (unknown), never zero.
 */
export function scoreFinding(input: RiskInput, weights: RiskWeights = DEFAULT_WEIGHTS): RiskResult {
  const sev = severityValue(input.upstreamSeverity);
  if (!sev) {
    return {
      riskScore: null,
      riskLevel: "unknown",
      factors: [
        {
          name: "Advisory severity",
          contribution: 0,
          reason: "The advisory has no usable severity data, so no risk score is assigned",
        },
      ],
    };
  }
  const exp = exposure(input);
  const factors: RiskFactor[] = [
    {
      name: "Advisory severity",
      contribution: round1(weights.severity * sev.value),
      reason: sev.reason,
    },
    {
      name: "Runtime exposure",
      contribution: round1(weights.exposure * exp.value),
      reason: exp.reason,
    },
  ];
  const riskScore = round1(weights.severity * sev.value + weights.exposure * exp.value);
  return { riskScore, riskLevel: riskLevelFor(riskScore), factors };
}
