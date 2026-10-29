import { Command, Option } from "commander";
import pkg from "../../package.json";
import { explainCommand } from "./commands/explain";
import { graphCommand } from "./commands/graph";
import { reportCommand } from "./commands/report";
import { scanCommand } from "./commands/scan";
import { REPORT_FORMATS } from "../reports/render";

const formatOption = () =>
  new Option("--format <format>", "output format").choices(REPORT_FORMATS).default("terminal");

export function buildProgram(): Command {
  const program = new Command();
  program
    .name("chainwatch")
    .description("Local-first dependency risk analyzer for npm projects")
    .version(pkg.version)
    .exitOverride();

  program
    .command("scan")
    .description("Scan a project for known vulnerable dependencies")
    .argument("[path]", "project directory", ".")
    .option("--config <file>", "configuration file")
    .option("--offline", "use cached advisory data only")
    .option("--no-cache", "bypass the advisory cache")
    .option("--verbose", "print diagnostics to stderr")
    .addOption(formatOption())
    .option("--output <file>", "write the report to a file instead of stdout")
    .action(async (path, options) => {
      process.exitCode = await scanCommand(path, options);
    });

  program
    .command("explain")
    .description("Explain the findings for one package (name or name@version)")
    .argument("<package>", "package name, optionally with @version")
    .argument("[path]", "project directory", ".")
    .option("--config <file>", "configuration file")
    .option("--offline", "use cached advisory data only")
    .option("--no-cache", "bypass the advisory cache")
    .option("--input <file>", "read findings from a scan.json instead of scanning")
    .action(async (spec, path, options) => {
      process.exitCode = await explainCommand(spec, path, options);
    });

  program
    .command("report")
    .description("Render a saved scan.json as a report")
    .requiredOption("--input <file>", "scan.json written by scan --format json")
    .addOption(formatOption())
    .option("--output <file>", "write the report to a file instead of stdout")
    .action(async (options) => {
      process.exitCode = await reportCommand(options);
    });

  program
    .command("graph", { hidden: true })
    .description("Print the dependency tree parsed from the lockfile")
    .argument("[path]", "project directory", ".")
    .option("--config <file>", "configuration file")
    .action(graphCommand);

  return program;
}
