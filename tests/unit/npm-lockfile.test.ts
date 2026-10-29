import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { LockfileError } from "../../src/core/errors";
import { indexGraph, shortestPaths } from "../../src/lockfile/graph";
import { parseNpmLockfile } from "../../src/lockfile/npm";

const fixtures = join(__dirname, "..", "fixtures");
const load = (...parts: string[]) => readFileSync(join(fixtures, ...parts), "utf8");
const parseFixture = (name: string) => parseNpmLockfile(load(name, "package-lock.json"));

const byId = (r: ReturnType<typeof parseFixture>, id: string) => {
  const node = r.graph.nodes.find((n) => n.id === id);
  if (!node) throw new Error(`missing node ${id}`);
  return node;
};

describe("parseNpmLockfile", () => {
  it("separates direct from transitive packages", () => {
    const { graph, warnings } = parseFixture("vulnerable");
    expect(warnings).toEqual([]);
    expect(graph.root).toEqual({ name: "vulnerable-app", version: "1.0.0" });
    const direct = graph.nodes.filter((n) => n.direct).map((n) => n.package.name);
    expect(direct).toEqual(["lodash", "mkdirp"]);
    const minimist = graph.nodes.find((n) => n.package.name === "minimist");
    expect(minimist).toMatchObject({ direct: false, dev: false, source: "registry" });
    expect(graph.edges.some((e) => e.from === "node_modules/mkdirp" && e.to === minimist?.id)).toBe(
      true,
    );
  });

  it("keeps every installed version of a package, including npm: aliases", () => {
    const r = parseFixture("multi-version");
    expect(byId(r, "node_modules/semver").package.version).toBe("7.5.4");
    const old = byId(r, "node_modules/semver-old");
    expect(old.package).toMatchObject({ name: "semver", version: "5.7.2" });
    expect(old.direct).toBe(true);
  });

  it("marks dev-only packages and resolves nested copies", () => {
    const r = parseFixture("dev-and-prod");
    expect(byId(r, "node_modules/is-number").dev).toBe(false);
    expect(byId(r, "node_modules/is-odd")).toMatchObject({ dev: true, direct: true });
    // is-odd needs a different is-number, which npm nests under it.
    const nested = byId(r, "node_modules/is-odd/node_modules/is-number");
    expect(nested).toMatchObject({ dev: true, direct: false });
    expect(nested.package.version).not.toBe("7.0.0");
    expect(
      r.graph.edges.some(
        (e) => e.from === "node_modules/is-odd" && e.to === nested.id && e.type === "prod",
      ),
    ).toBe(true);
  });

  it("treats workspace members as workspaces and follows links to them", () => {
    const r = parseFixture("workspaces");
    expect(byId(r, "packages/app").source).toBe("workspace");
    expect(byId(r, "packages/lib").source).toBe("workspace");
    // The node_modules/* link entries are aliases, not nodes of their own.
    expect(r.graph.nodes.some((n) => n.id === "node_modules/lib")).toBe(false);
    expect(r.graph.edges.some((e) => e.from === "packages/app" && e.to === "packages/lib")).toBe(
      true,
    );
    // Packages declared by a workspace are direct.
    expect(byId(r, "node_modules/is-number").direct).toBe(true);
    expect(byId(r, "node_modules/is-odd").direct).toBe(true);
  });

  it("does not treat git and file: dependencies as registry packages", () => {
    const r = parseFixture("non-registry");
    expect(byId(r, "node_modules/is-number").source).toBe("registry");
    expect(byId(r, "node_modules/left-pad").source).toBe("non-registry");
    expect(byId(r, "local-lib").source).toBe("non-registry");
  });

  it("is deterministic regardless of entry order", () => {
    const text = load("vulnerable", "package-lock.json");
    const json = JSON.parse(text) as { packages: Record<string, unknown> };
    const reversed = {
      ...json,
      packages: Object.fromEntries(Object.entries(json.packages).reverse()),
    };
    expect(parseNpmLockfile(JSON.stringify(reversed)).graph).toEqual(parseNpmLockfile(text).graph);
  });

  it("reports a missing required dependency as a warning", () => {
    const text = JSON.stringify({
      lockfileVersion: 3,
      packages: { "": { name: "x", dependencies: { ghost: "^1.0.0" } } },
    });
    expect(parseNpmLockfile(text).warnings).toEqual([
      "Could not resolve ghost@^1.0.0 required by the project",
    ]);
  });

  it("is not confused by a __proto__ package key", () => {
    const text =
      '{"lockfileVersion":3,"packages":{"":{"name":"x"},"node_modules/__proto__":{"version":"1.0.0"}}}';
    const { graph } = parseNpmLockfile(text);
    expect(graph.nodes.map((n) => n.package.name)).toEqual(["__proto__"]);
    expect(({} as Record<string, unknown>).version).toBeUndefined();
  });

  describe("malformed input", () => {
    const cases: [string, string][] = [
      ["not-json.json", "LOCKFILE_INVALID"],
      ["lockfile-v1.json", "LOCKFILE_UNSUPPORTED_VERSION"],
      ["no-packages.json", "LOCKFILE_INVALID"],
      ["bad-entry.json", "LOCKFILE_INVALID"],
    ];
    it.each(cases)("rejects %s with %s", (file, code) => {
      const text = load("malformed", file);
      expect(() => parseNpmLockfile(text)).toThrow(LockfileError);
      try {
        parseNpmLockfile(text);
      } catch (e) {
        expect((e as LockfileError).code).toBe(code);
      }
    });
  });
});

describe("shortestPaths", () => {
  it("returns the path from the project to a transitive package", () => {
    const index = indexGraph(parseFixture("vulnerable").graph);
    const minimist = [...index.nodes.values()].find((n) => n.package.name === "minimist");
    const { paths, count } = shortestPaths(index, [minimist?.id as string]);
    expect(count).toBe(1);
    expect(paths).toHaveLength(1);
    expect(paths[0]?.[0]).toBe("vulnerable-app");
    expect(paths[0]?.[1]).toMatch(/^mkdirp@/);
    expect(paths[0]?.at(-1)).toMatch(/^minimist@/);
  });

  it("counts shortest paths in a diamond without enumerating them all", () => {
    // root -> a,b -> c,  c -> d
    const mk = (id: string) => ({
      id,
      package: { ecosystem: "npm" as const, name: id, version: "1.0.0" },
      direct: false,
      dev: false,
      optional: false,
      peer: false,
      source: "registry" as const,
    });
    const e = (from: string, to: string) => ({ from, to, range: "*", type: "prod" as const });
    const index = indexGraph({
      root: { name: "app", version: "1.0.0" },
      nodes: ["a", "b", "c", "d"].map(mk),
      edges: [e("", "a"), e("", "b"), e("a", "c"), e("b", "c"), e("c", "d")],
    });
    const result = shortestPaths(index, ["d"], 1);
    expect(result.count).toBe(2);
    expect(result.paths).toEqual([["app", "a@1.0.0", "c@1.0.0", "d@1.0.0"]]);
  });

  it("returns nothing for an unreachable package and survives cycles", () => {
    const mk = (id: string) => ({
      id,
      package: { ecosystem: "npm" as const, name: id, version: "1.0.0" },
      direct: false,
      dev: false,
      optional: false,
      peer: false,
      source: "registry" as const,
    });
    const e = (from: string, to: string) => ({ from, to, range: "*", type: "prod" as const });
    const index = indexGraph({
      root: { name: "app", version: "1.0.0" },
      nodes: ["a", "b", "lonely"].map(mk),
      edges: [e("", "a"), e("a", "b"), e("b", "a")],
    });
    expect(shortestPaths(index, ["lonely"])).toEqual({ paths: [], count: 0 });
    expect(shortestPaths(index, ["b"]).count).toBe(1);
  });
});
