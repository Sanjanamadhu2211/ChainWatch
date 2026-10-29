import { loadProject } from "../../core/project";
import { indexGraph, nodeLabel } from "../../lockfile/graph";
import { ROOT_ID, type DependencyNode } from "../../core/types";

export interface GraphOptions {
  config?: string;
}

function tags(node: DependencyNode): string {
  const t = [
    node.dev && "dev",
    node.optional && "optional",
    node.peer && "peer",
    node.source !== "registry" && node.source,
  ].filter(Boolean);
  return t.length ? ` [${t.join(", ")}]` : "";
}

/** Prints the dependency tree. A package that already appeared is marked (*) and not expanded again. */
export async function graphCommand(path: string, options: GraphOptions): Promise<void> {
  const { lockfile } = await loadProject(path, options.config);
  const { graph, warnings } = lockfile;
  const index = indexGraph(graph);
  const seen = new Set<string>();
  const lines = [`${graph.root.name}@${graph.root.version}`];

  const walk = (id: string, prefix: string) => {
    const kids = index.children.get(id) ?? [];
    kids.forEach((childId, i) => {
      const node = index.nodes.get(childId) as DependencyNode;
      const last = i === kids.length - 1;
      const repeated = seen.has(childId);
      lines.push(
        `${prefix}${last ? "└── " : "├── "}${nodeLabel(node)}${tags(node)}${repeated ? " (*)" : ""}`,
      );
      if (!repeated) {
        seen.add(childId);
        walk(childId, prefix + (last ? "    " : "│   "));
      }
    });
  };
  walk(ROOT_ID, "");

  console.log(lines.join("\n"));
  console.log(`\n${graph.nodes.length} packages installed`);
  for (const w of warnings) console.error(`warning: ${w}`);
}
