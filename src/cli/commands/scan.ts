import { DEFAULT_OSV_URL, OsvClient } from "../../advisories/osv-client";
import { runScan } from "../../core/scan";
import { renderTerminal } from "../../reports/terminal";

export interface ScanCommandOptions {
  config?: string;
  offline?: boolean;
  cache?: boolean; // commander turns --no-cache into cache: false
  verbose?: boolean;
}

/** Returns the process exit code. */
export async function scanCommand(path: string, options: ScanCommandOptions): Promise<number> {
  // CHAINWATCH_OSV_URL points the scanner at a mirror or a test server.
  const provider = new OsvClient({ baseUrl: process.env.CHAINWATCH_OSV_URL ?? DEFAULT_OSV_URL });
  const result = await runScan({
    path,
    configPath: options.config,
    offline: options.offline,
    noCache: options.cache === false,
    provider,
    log: options.verbose ? (m) => console.error(`[chainwatch] ${m}`) : undefined,
  });
  console.log(renderTerminal(result));
  return result.status === "complete" ? 0 : 3;
}
