import { writeFile } from "node:fs/promises";
import { ChainwatchError } from "../core/errors";
import type { ScanResult } from "../core/types";
import { renderHtml } from "./html";
import { renderJson } from "./json";
import { renderTerminal } from "./terminal";

export const REPORT_FORMATS = ["terminal", "json", "html"] as const;
export type ReportFormat = (typeof REPORT_FORMATS)[number];

export function renderReport(result: ScanResult, format: ReportFormat): string {
  if (format === "json") return renderJson(result);
  if (format === "html") return renderHtml(result);
  return renderTerminal(result);
}

/** Writes to a file when `output` is set, otherwise to stdout. */
export async function emitReport(text: string, output?: string): Promise<void> {
  const body = text.endsWith("\n") ? text : `${text}\n`;
  if (!output) {
    process.stdout.write(body);
    return;
  }
  try {
    await writeFile(output, body);
  } catch {
    throw new ChainwatchError("OUTPUT_FAILED", `Cannot write the report to ${output}`, 2);
  }
}
