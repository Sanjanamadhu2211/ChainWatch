import { Command } from "commander";
import pkg from "../../package.json";
import { explainCommand } from "./commands/explain";
import { graphCommand } from "./commands/graph";
import { scanCommand } from "./commands/scan";

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
    .action(async (spec, path, options) => {
      process.exitCode = await explainCommand(spec, path, options);
    });

  program
    .command("graph", { hidden: true })
    .description("Print the dependency tree parsed from the lockfile")
    .argument("[path]", "project directory", ".")
    .option("--config <file>", "configuration file")
    .action(graphCommand);

  return program;
}
