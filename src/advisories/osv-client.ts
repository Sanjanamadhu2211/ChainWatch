import type { Advisory, PackageId } from "../core/types";
import { packageKey, type AdvisoryProvider, type Lookup } from "./provider";
import { parseOsvVuln, queryBatchResponseSchema } from "./schema";

export const DEFAULT_OSV_URL = "https://api.osv.dev";

export interface OsvClientOptions {
  baseUrl?: string;
  fetch?: typeof fetch;
  timeoutMs?: number;
  maxRetries?: number;
  /** Queries per querybatch request. OSV documents a limit of 1000. */
  batchSize?: number;
  /** Parallel HTTP requests. */
  concurrency?: number;
  userAgent?: string;
  sleep?: (ms: number) => Promise<void>;
}

class OsvError extends Error {}

const MAX_PAGES = 50;
const MAX_BACKOFF_MS = 8000;
const MAX_RETRY_AFTER_MS = 30_000;

export class OsvClient implements AdvisoryProvider {
  private readonly baseUrl: string;
  private readonly fetchFn: typeof fetch;
  private readonly timeoutMs: number;
  private readonly maxRetries: number;
  private readonly batchSize: number;
  private readonly concurrency: number;
  private readonly userAgent: string;
  private readonly sleep: (ms: number) => Promise<void>;

  constructor(options: OsvClientOptions = {}) {
    this.baseUrl = (options.baseUrl ?? DEFAULT_OSV_URL).replace(/\/+$/, "");
    this.fetchFn = options.fetch ?? fetch;
    this.timeoutMs = options.timeoutMs ?? 15_000;
    this.maxRetries = options.maxRetries ?? 3;
    this.batchSize = options.batchSize ?? 1000;
    this.concurrency = options.concurrency ?? 6;
    this.userAgent = options.userAgent ?? "chainwatch";
    this.sleep = options.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
  }

  async queryBatch(packages: PackageId[]): Promise<Map<string, Lookup<string[]>>> {
    const unique = new Map(packages.map((p) => [packageKey(p), p]));
    const ids = new Map<string, Set<string>>();
    const failed = new Map<string, string>();
    for (const key of unique.keys()) ids.set(key, new Set());

    type Item = { key: string; pkg: PackageId; token?: string };
    let pending: Item[] = [...unique].map(([key, pkg]) => ({ key, pkg }));

    for (let page = 0; pending.length > 0; page++) {
      if (page >= MAX_PAGES) {
        for (const item of pending) failed.set(item.key, "OSV returned too many result pages");
        break;
      }
      const chunks: Item[][] = [];
      for (let i = 0; i < pending.length; i += this.batchSize)
        chunks.push(pending.slice(i, i + this.batchSize));

      const next: Item[] = [];
      await mapPool(chunks, this.concurrency, async (chunk) => {
        try {
          const body = {
            queries: chunk.map((item) => ({
              package: { name: item.pkg.name, ecosystem: "npm" },
              version: item.pkg.version,
              ...(item.token ? { page_token: item.token } : {}),
            })),
          };
          const parsed = queryBatchResponseSchema.parse(
            await this.request("POST", "/v1/querybatch", body),
          );
          if (parsed.results.length !== chunk.length) {
            throw new OsvError("OSV returned a different number of results than queries");
          }
          parsed.results.forEach((result, i) => {
            const item = chunk[i] as Item;
            for (const v of result.vulns ?? []) ids.get(item.key)?.add(v.id);
            if (result.next_page_token) next.push({ ...item, token: result.next_page_token });
          });
        } catch (e) {
          for (const item of chunk) failed.set(item.key, describe(e));
        }
      });
      // A failed package must not keep paginating.
      pending = next.filter((item) => !failed.has(item.key));
    }

    const out = new Map<string, Lookup<string[]>>();
    for (const [key, set] of ids) {
      const error = failed.get(key);
      out.set(
        key,
        error !== undefined ? { ok: false, error } : { ok: true, value: [...set].sort() },
      );
    }
    return out;
  }

  async getAdvisories(ids: string[]): Promise<Map<string, Lookup<Advisory>>> {
    const out = new Map<string, Lookup<Advisory>>();
    await mapPool([...new Set(ids)], this.concurrency, async (id) => {
      try {
        const json = await this.request("GET", `/v1/vulns/${encodeURIComponent(id)}`);
        out.set(id, { ok: true, value: parseOsvVuln(json) });
      } catch (e) {
        out.set(id, { ok: false, error: describe(e) });
      }
    });
    return out;
  }

  /** One request with a timeout and bounded retries for transient failures. */
  private async request(method: "GET" | "POST", path: string, body?: unknown): Promise<unknown> {
    let lastError = "unknown error";
    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      let retryAfterMs: number | undefined;
      try {
        const res = await this.fetchFn(this.baseUrl + path, {
          method,
          headers: {
            "user-agent": this.userAgent,
            ...(body !== undefined ? { "content-type": "application/json" } : {}),
          },
          body: body !== undefined ? JSON.stringify(body) : undefined,
          signal: AbortSignal.timeout(this.timeoutMs),
        });
        if (res.ok) {
          try {
            return await res.json();
          } catch {
            throw new OsvError("OSV returned a response that is not valid JSON");
          }
        }
        lastError = `OSV responded with HTTP ${res.status}`;
        // Only rate limits and server errors are worth retrying; other 4xx will not change.
        if (res.status !== 429 && res.status < 500) throw new OsvError(lastError);
        retryAfterMs = parseRetryAfter(res.headers.get("retry-after"));
      } catch (e) {
        if (e instanceof OsvError) throw e;
        lastError = `could not reach OSV (${describe(e)})`;
      }
      if (attempt < this.maxRetries) {
        const backoff = Math.min(500 * 2 ** attempt, MAX_BACKOFF_MS) * (0.5 + Math.random() / 2);
        await this.sleep(retryAfterMs ?? backoff);
      }
    }
    throw new OsvError(`${lastError} after ${this.maxRetries + 1} attempts`);
  }
}

function parseRetryAfter(header: string | null): number | undefined {
  if (!header) return undefined;
  const seconds = Number(header);
  return Number.isFinite(seconds) && seconds >= 0
    ? Math.min(seconds * 1000, MAX_RETRY_AFTER_MS)
    : undefined;
}

function describe(e: unknown): string {
  if (e instanceof Error) {
    if (e.name === "TimeoutError") return "request timed out";
    if (e.name === "ZodError") return "OSV returned a response in an unexpected format";
    return e.message;
  }
  return String(e);
}

/** Runs `fn` over `items` with at most `limit` in flight. */
async function mapPool<T>(
  items: T[],
  limit: number,
  fn: (item: T) => Promise<void>,
): Promise<void> {
  let next = 0;
  const worker = async () => {
    while (next < items.length) await fn(items[next++] as T);
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
}
