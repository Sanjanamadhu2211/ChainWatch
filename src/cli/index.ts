import { CommanderError } from "commander";
import { ChainwatchError } from "../core/errors";
import { buildProgram } from "./cli";

async function main(): Promise<number> {
  try {
    await buildProgram().parseAsync(process.argv);
    return Number(process.exitCode ?? 0);
  } catch (e) {
    // Commander already printed usage problems; help and --version are not failures.
    if (e instanceof CommanderError) return e.exitCode === 0 ? 0 : 2;
    if (e instanceof ChainwatchError) {
      console.error(`chainwatch: ${e.message}`);
      return e.exitCode;
    }
    console.error(`chainwatch: unexpected error: ${(e as Error).stack ?? String(e)}`);
    return 3;
  }
}

process.exitCode = await main();
