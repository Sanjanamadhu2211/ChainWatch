import {
  ROOT_ID,
  type DependencyEdge,
  type DependencyGraph,
  type DependencyNode,
} from "../core/types";

export interface GraphIndex {
  graph: DependencyGraph;
  nodes: Map<string, DependencyNode>;
  children: Map<string, string[]>;
  parents: Map<string, string[]>;
}

export function nodeLabel(node: DependencyNode): string {
  return `${node.package.name}@${node.package.version}`;
}

export function indexGraph(graph: DependencyGraph): GraphIndex {
  const nodes = new Map(graph.nodes.map((n) => [n.id, n]));
  const children = new Map<string, string[]>();
  const parents = new Map<string, string[]>();
  const link = (map: Map<string, string[]>, key: string, value: string) => {
    const list = map.get(key);
    if (!list) map.set(key, [value]);
    else if (!list.includes(value)) list.push(value);
  };
  for (const e of graph.edges as DependencyEdge[]) {
    link(children, e.from, e.to);
    link(parents, e.to, e.from);
  }
  return { graph, nodes, children, parents };
}

/** Drops dev-only packages and every edge that touches them. */
export function withoutDev(graph: DependencyGraph): DependencyGraph {
  const nodes = graph.nodes.filter((n) => !n.dev);
  const kept = new Set(nodes.map((n) => n.id));
  kept.add(ROOT_ID);
  return {
    ...graph,
    nodes,
    edges: graph.edges.filter((e) => kept.has(e.from) && kept.has(e.to)),
  };
}

export interface PathsResult {
  /** Up to `max` shortest paths, as "name@version" labels starting with the project name. */
  paths: string[][];
  /** Number of shortest paths. Longer paths are deliberately not counted. */
  count: number;
}

/**
 * Shortest paths from the project to any of `targetIds`. Counting uses the BFS layers, so
 * diamond-shaped graphs cost O(edges) instead of exploding.
 */
export function shortestPaths(index: GraphIndex, targetIds: string[], max = 5): PathsResult {
  const dist = new Map<string, number>([[ROOT_ID, 0]]);
  const ways = new Map<string, number>([[ROOT_ID, 1]]);
  const queue = [ROOT_ID];
  for (let i = 0; i < queue.length; i++) {
    const id = queue[i] as string;
    const d = dist.get(id) as number;
    for (const child of index.children.get(id) ?? []) {
      if (!dist.has(child)) {
        dist.set(child, d + 1);
        queue.push(child);
      }
      if (dist.get(child) === d + 1)
        ways.set(child, (ways.get(child) ?? 0) + (ways.get(id) as number));
    }
  }

  const reachable = targetIds.filter((t) => dist.has(t));
  if (reachable.length === 0) return { paths: [], count: 0 };
  const best = Math.min(...reachable.map((t) => dist.get(t) as number));
  const targets = reachable.filter((t) => dist.get(t) === best).sort();
  const count = targets.reduce((sum, t) => sum + (ways.get(t) as number), 0);

  const labelOf = (id: string) =>
    id === ROOT_ID ? index.graph.root.name : nodeLabel(index.nodes.get(id) as DependencyNode);
  const paths: string[][] = [];
  const walk = (id: string, suffix: string[]) => {
    if (paths.length >= max) return;
    const here = [labelOf(id), ...suffix];
    if (id === ROOT_ID) {
      paths.push(here);
      return;
    }
    const d = dist.get(id) as number;
    for (const parent of [...(index.parents.get(id) ?? [])].sort()) {
      if (dist.get(parent) === d - 1) walk(parent, here);
    }
  };
  for (const t of targets) walk(t, []);
  return { paths, count };
}
