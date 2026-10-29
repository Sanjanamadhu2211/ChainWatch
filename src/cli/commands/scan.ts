import { DEFAULT_OSV_URL, OsvClient } from "../../advisories/osv-client";
import { runScan } from "../../core/scan";
import type { ScanResult } from "../../core/types";
import type { FailOn } from "../../policy/evaluate";
import { emitReport, renderReport, type ReportFormat } from "../../reports/render";

export interface ScanCommandOptions {
  config?: string;
  offline?: boolean;
  cache?: boolean; // commander turns --no-cache into cache: false
  verbose?: boolean;
  failOn?: FailOn;
}

export interface ScanOutputOptions {
  format: ReportFormat;
  output?: string;
}

/** Shared by scan and explain so both talk to OSV the same way. */
export function runProjectScan(path: string, options: ScanCommandOptions): Promise<ScanResult> {
  // CHAINWATCH_OSV_URL points the scanner at a mirror or a test server.
  const provider = new OsvClient({ baseUrl: process.env.CHAINWATCH_OSV_URL ?? DEFAULT_OSV_URL });
  return runScan({
    path,
    configPath: options.config,
    offline: options.offline,
    noCache: options.cache === false,
    failOn: options.failOn,
    provider,
    log: options.verbose ? (m) => console.error(`[chainwatch] ${m}`) : undefined,
  });
}

/** An incomplete scan outranks a policy failure: 3 means the result cannot be trusted either way. */
export function exitCodeFor(result: ScanResult): number {
  if (result.status !== "complete") return 3;
  return result.policy?.passed === false ? 1 : 0;
}

/** Returns the process exit code. */
export async function scanCommand(
  path: string,
  options: ScanCommandOptions & ScanOutputOptions,
): Promise<number> {
  const result = await runProjectScan(path, options);
  await emitReport(renderReport(result, options.format), options.output);
  return exitCodeFor(result);
}
