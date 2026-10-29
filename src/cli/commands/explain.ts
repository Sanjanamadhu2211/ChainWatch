import { ChainwatchError } from "../../core/errors";
import { renderExplain } from "../../reports/terminal";
import { runProjectScan, type ScanCommandOptions } from "./scan";

export interface PackageSpec {
  name: string;
  version?: string;
}

/** Accepts `name` or `name@version`, including scoped names such as `@scope/name@1.2.3`. */
export function parsePackageSpec(spec: string): PackageSpec {
  const at = spec.lastIndexOf("@");
  const name = at > 0 ? spec.slice(0, at) : spec;
  const version = at > 0 ? spec.slice(at + 1) : undefined;
  // A leading "@" is only valid as a scope, so "@" and "@1.2.3" are rejected.
  const badName = !name || (name.startsWith("@") && !name.includes("/"));
  if (badName || version === "") {
    throw new ChainwatchError("INVALID_PACKAGE", `Invalid package "${spec}": use name or name@version`);
  }
  return { name, version };
}

/** Returns the process exit code. Explains every finding that matches the package. */
export async function explainCommand(
  spec: string,
  path: string,
  options: ScanCommandOptions,
): Promise<number> {
  const target = parsePackageSpec(spec);
  const result = await runProjectScan(path, options);
  const matches = result.findings.filter(
    (f) =>
      f.package.name === target.name && (target.version === undefined || f.package.version === target.version),
  );
  console.log(renderExplain(result, matches, spec));
  return result.status === "complete" ? 0 : 3;
}
