import { readFile, stat } from "node:fs/promises";
import { z } from "zod";
import { LockfileError } from "../core/errors";
import {
  ROOT_ID,
  type DependencyEdge,
  type DependencyGraph,
  type DependencyNode,
} from "../core/types";

/** Lockfiles above this size are rejected before parsing. */
export const MAX_LOCKFILE_BYTES = 50 * 1024 * 1024;

const depMap = z.record(z.string(), z.string()).optional();

const entrySchema = z.object({
  name: z.string().optional(),
  version: z.string().optional(),
  resolved: z.string().optional(),
  link: z.boolean().optional(),
  dev: z.boolean().optional(),
  optional: z.boolean().optional(),
  devOptional: z.boolean().optional(),
  peer: z.boolean().optional(),
  inBundle: z.boolean().optional(),
  dependencies: depMap,
  devDependencies: depMap,
  optionalDependencies: depMap,
  peerDependencies: depMap,
  workspaces: z
    .union([z.array(z.string()), z.object({ packages: z.array(z.string()).optional() })])
    .optional(),
});

type Entry = z.infer<typeof entrySchema>;

export interface ParsedLockfile {
  graph: DependencyGraph;
  /** Problems that do not stop the scan, such as a dependency the lockfile does not resolve. */
  warnings: string[];
}

const DEP_FIELDS = [
  ["dependencies", "prod"],
  ["devDependencies", "dev"],
  ["optionalDependencies", "optional"],
  ["peerDependencies", "peer"],
] as const;

// npm registry tarballs look like <host>/<name>/-/<file>.tgz; git, file: and codeload URLs do not.
const REGISTRY_TARBALL = /^https?:\/\/[^?#]+\/-\/[^/]+\.tgz$/;

export async function readNpmLockfile(path: string): Promise<ParsedLockfile> {
  let size: number;
  try {
    size = (await stat(path)).size;
  } catch {
    throw new LockfileError("LOCKFILE_NOT_FOUND", `Could not find ${path}`);
  }
  if (size > MAX_LOCKFILE_BYTES) {
    throw new LockfileError(
      "LOCKFILE_TOO_LARGE",
      `${path} is larger than ${MAX_LOCKFILE_BYTES / 1024 / 1024} MiB`,
    );
  }
  return parseNpmLockfile(await readFile(path, "utf8"));
}

export function parseNpmLockfile(text: string): ParsedLockfile {
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    throw new LockfileError("LOCKFILE_INVALID", "The lockfile is not valid JSON");
  }
  if (typeof json !== "object" || json === null || Array.isArray(json)) {
    throw new LockfileError("LOCKFILE_INVALID", "The lockfile must be a JSON object");
  }
  const { lockfileVersion, packages } = json as Record<string, unknown>;
  if (lockfileVersion !== 2 && lockfileVersion !== 3) {
    throw new LockfileError(
      "LOCKFILE_UNSUPPORTED_VERSION",
      `Unsupported lockfileVersion ${String(lockfileVersion)}. Chainwatch reads versions 2 and 3; ` +
        "run `npm install` with npm 7 or newer to upgrade the lockfile.",
    );
  }
  if (typeof packages !== "object" || packages === null || Array.isArray(packages)) {
    throw new LockfileError("LOCKFILE_INVALID", 'The lockfile has no "packages" section');
  }

  // A Map keeps odd keys such as "__proto__" from ever touching an object prototype.
  const entries = new Map<string, Entry>();
  for (const [key, raw] of Object.entries(packages)) {
    const parsed = entrySchema.safeParse(raw);
    if (!parsed.success) {
      const issue = parsed.error.issues[0];
      throw new LockfileError(
        "LOCKFILE_INVALID",
        `Invalid lockfile entry "${key}": ${issue?.path.join(".") ?? ""} ${issue?.message ?? ""}`.trim(),
      );
    }
    entries.set(key, parsed.data);
  }

  const rootEntry = entries.get("");
  if (!rootEntry) {
    throw new LockfileError("LOCKFILE_INVALID", 'The lockfile has no root ("") package entry');
  }
  const hasWorkspaces = rootEntry.workspaces !== undefined;

  const warnings: string[] = [];
  const nodes = new Map<string, DependencyNode>();
  const owners: string[] = [ROOT_ID];

  for (const [key, entry] of entries) {
    if (key === ROOT_ID || entry.link) continue;
    const isWorkspace = !key.includes("node_modules/") && hasWorkspaces;
    nodes.set(key, {
      id: key,
      package: {
        ecosystem: "npm",
        name: entry.name ?? nameFromKey(key),
        version: entry.version ?? "0.0.0",
      },
      direct: isWorkspace,
      dev: entry.dev === true,
      optional: entry.optional === true || entry.devOptional === true,
      peer: entry.peer === true,
      source: isWorkspace ? "workspace" : isRegistry(key, entry) ? "registry" : "non-registry",
    });
    owners.push(key);
  }

  const edgeKeys = new Set<string>();
  const edges: DependencyEdge[] = [];
  const addEdge = (edge: DependencyEdge) => {
    const k = `${edge.from}\0${edge.to}\0${edge.type}`;
    if (edgeKeys.has(k)) return;
    edgeKeys.add(k);
    edges.push(edge);
  };

  for (const owner of owners) {
    const entry = entries.get(owner) as Entry;
    for (const [field, type] of DEP_FIELDS) {
      for (const [name, range] of Object.entries(entry[field] ?? {})) {
        const to = resolveDependency(entries, owner, name);
        if (to === undefined) {
          // Optional and peer dependencies are often legitimately not installed.
          if (type === "prod" || type === "dev") {
            warnings.push(
              `Could not resolve ${name}@${range} required by ${owner || "the project"}`,
            );
          }
          continue;
        }
        addEdge({ from: owner, to, range, type });
      }
    }
  }
  for (const node of nodes.values()) {
    if (node.source === "workspace")
      addEdge({ from: ROOT_ID, to: node.id, range: "workspace", type: "prod" });
  }

  // A package is direct when the project or one of its workspaces declares it.
  for (const edge of edges) {
    const from = edge.from === ROOT_ID ? undefined : nodes.get(edge.from);
    if (edge.from === ROOT_ID || from?.source === "workspace") {
      const target = nodes.get(edge.to);
      if (target) target.direct = true;
    }
  }

  const sortedNodes = [...nodes.values()].sort((a, b) => compare(a.id, b.id));
  edges.sort((a, b) => compare(a.from, b.from) || compare(a.to, b.to) || compare(a.type, b.type));

  return {
    graph: {
      root: { name: rootEntry.name ?? "application", version: rootEntry.version ?? "0.0.0" },
      nodes: sortedNodes,
      edges,
    },
    warnings,
  };
}

function compare(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function nameFromKey(key: string): string {
  const marker = "node_modules/";
  const idx = key.lastIndexOf(marker);
  if (idx === -1) return key.split("/").pop() ?? key;
  return key.slice(idx + marker.length);
}

// shortcut: a `file:` directory outside `workspaces` is classed as non-registry, not as a local project
function isRegistry(key: string, entry: Entry): boolean {
  if (!key.includes("node_modules/")) return false;
  if (entry.resolved === undefined) return entry.inBundle === true;
  return REGISTRY_TARBALL.test(entry.resolved);
}

/** Directory whose node_modules would be searched after `scope`'s own, or null at the top. */
function parentScope(scope: string): string | null {
  if (scope === ROOT_ID) return null;
  const idx = scope.lastIndexOf("node_modules/");
  return idx <= 0 ? ROOT_ID : scope.slice(0, idx - 1);
}

/** Node's resolution: look in the owner's node_modules, then walk up through its ancestors. */
function resolveDependency(
  entries: Map<string, Entry>,
  owner: string,
  name: string,
): string | undefined {
  for (let scope: string | null = owner; scope !== null; scope = parentScope(scope)) {
    const candidate = scope === ROOT_ID ? `node_modules/${name}` : `${scope}/node_modules/${name}`;
    const entry = entries.get(candidate);
    if (!entry) continue;
    if (!entry.link) return candidate;
    // A link (workspace or file: dependency) points at the real entry elsewhere in the tree.
    return entry.resolved !== undefined && entries.has(entry.resolved) ? entry.resolved : undefined;
  }
  return undefined;
}
