import { access } from "node:fs/promises";
import { resolve } from "node:path";
import { LockfileError } from "./errors";
import { withoutDev } from "../lockfile/graph";
import { readNpmLockfile, type ParsedLockfile } from "../lockfile/npm";
import { loadConfig, type Config } from "../policy/config";

export interface Project {
  rootPath: string;
  config: Config;
  lockfilePath: string;
  lockfile: ParsedLockfile;
}

/** Resolves the project directory, its configuration and its lockfile (dev dependencies filtered per config). */
export async function loadProject(path: string, configPath?: string): Promise<Project> {
  const rootPath = resolve(path);
  const config = await loadConfig(rootPath, configPath);

  let lockfilePath: string | undefined;
  for (const name of config.scan.lockfiles) {
    const candidate = resolve(rootPath, name);
    try {
      await access(candidate);
      lockfilePath = candidate;
      break;
    } catch {
      // try the next configured lockfile
    }
  }
  if (!lockfilePath) {
    throw new LockfileError(
      "LOCKFILE_NOT_FOUND",
      `No lockfile found in ${rootPath} (looked for ${config.scan.lockfiles.join(", ")})`,
    );
  }

  const lockfile = await readNpmLockfile(lockfilePath);
  if (!config.scan.includeDevDependencies) {
    lockfile.graph = withoutDev(lockfile.graph);
  }
  return { rootPath, config, lockfilePath, lockfile };
}
