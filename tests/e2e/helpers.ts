import { execFile, execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { join } from "node:path";

export const repoRoot = join(__dirname, "..", "..");
export const fixture = (name: string) => join(repoRoot, "tests", "fixtures", name);

/** Builds the CLI once per test file so e2e tests run the real compiled binary. */
export function buildCli(): void {
  execFileSync(
    process.execPath,
    [join(repoRoot, "node_modules", "tsup", "dist", "cli-default.js")],
    { cwd: repoRoot, stdio: "ignore" },
  );
}

export interface CliResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

/** Async so an in-process fake OSV server can answer while the CLI runs. */
export function runCli(args: string[], env: Record<string, string> = {}): Promise<CliResult> {
  return new Promise((resolve) => {
    execFile(
      process.execPath,
      [join(repoRoot, "dist", "index.js"), ...args],
      { encoding: "utf8", env: { ...process.env, ...env } },
      (error, stdout, stderr) => {
        const code = error ? (typeof error.code === "number" ? error.code : 1) : 0;
        resolve({ code, stdout, stderr });
      },
    );
  });
}

const osvDir = join(repoRoot, "tests", "fixtures", "osv");

/** A local stand-in for api.osv.dev that replays the captured fixtures. */
export async function startFakeOsv(
  options: { status?: number } = {},
): Promise<{ url: string; server: Server; requests: string[] }> {
  const queries = JSON.parse(readFileSync(join(osvDir, "queries.json"), "utf8")) as Record<
    string,
    string[]
  >;
  const requests: string[] = [];
  const server = createServer((req, res) => {
    requests.push(`${req.method} ${req.url}`);
    if (options.status) {
      res.writeHead(options.status).end("unavailable");
      return;
    }
    if (req.method === "POST" && req.url === "/v1/querybatch") {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        const { queries: qs } = JSON.parse(body) as {
          queries: { package: { name: string }; version: string }[];
        };
        const results = qs.map((q) => ({
          vulns: (queries[`${q.package.name}@${q.version}`] ?? []).map((id) => ({ id })),
        }));
        res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ results }));
      });
      return;
    }
    const id = req.url?.match(/^\/v1\/vulns\/(.+)$/)?.[1];
    try {
      const file = join(osvDir, "vulns", `${decodeURIComponent(id ?? "")}.json`);
      res.writeHead(200, { "content-type": "application/json" }).end(readFileSync(file));
    } catch {
      res.writeHead(404).end("not found");
    }
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, server, requests };
}
