import { readScanResult } from "../../reports/schema";
import { emitReport, renderReport, type ReportFormat } from "../../reports/render";

export interface ReportCommandOptions {
  input: string;
  format: ReportFormat;
  output?: string;
}

/** Renders a saved scan.json. Returns the exit code the scan would have had. */
export async function reportCommand(options: ReportCommandOptions): Promise<number> {
  const result = await readScanResult(options.input);
  await emitReport(renderReport(result, options.format), options.output);
  return result.status === "complete" ? 0 : 3;
}
