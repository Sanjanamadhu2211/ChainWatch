import { Command } from "commander";
import pkg from "../../package.json";
import { graphCommand } from "./commands/graph";

export function buildProgram(): Command {
  const program = new Command();
  program
    .name("chainwatch")
    .description("Local-first dependency risk analyzer for npm projects")
    .version(pkg.version)
    .exitOverride();

  program
    .command("graph", { hidden: true })
    .description("Print the dependency tree parsed from the lockfile")
    .argument("[path]", "project directory", ".")
    .option("--config <file>", "configuration file")
    .action(graphCommand);

  return program;
}
