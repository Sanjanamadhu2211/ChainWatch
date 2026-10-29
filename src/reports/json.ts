import type { ScanResult } from "../core/types";

/** The scan.json contract: the full ScanResult, validated by docs/schema/scan-result.schema.json. */
export function renderJson(result: ScanResult): string {
  return `${JSON.stringify(result, null, 2)}\n`;
}
