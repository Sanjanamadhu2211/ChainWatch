import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { z } from "zod";
import type { Advisory } from "../core/types";
import { advisorySchema } from "./schema";

const CACHE_FILE = "osv-cache.json";
// shortcut: entries older than this are dropped on save; make it configurable if anyone needs offline data for longer
const MAX_ENTRY_AGE_MS = 30 * 24 * 60 * 60 * 1000;

const fileSchema = z.object({
  version: z.literal(1),
  queries: z.record(
    z.string(),
    z.object({ ids: z.array(z.string()), fetchedAt: z.iso.datetime() }),
  ),
  advisories: z.record(
    z.string(),
    z.object({ advisory: advisorySchema, fetchedAt: z.iso.datetime() }),
  ),
});

export interface CacheEntry<T> {
  value: T;
  fetchedAt: Date;
}

/** OS-appropriate user cache directory. CHAINWATCH_CACHE_DIR overrides it. */
export function defaultCacheDir(env = process.env): string {
  if (env.CHAINWATCH_CACHE_DIR) return env.CHAINWATCH_CACHE_DIR;
  if (process.platform === "win32") {
    return join(env.LOCALAPPDATA ?? join(homedir(), "AppData", "Local"), "chainwatch", "Cache");
  }
  if (process.platform === "darwin") return join(homedir(), "Library", "Caches", "chainwatch");
  return join(env.XDG_CACHE_HOME ?? join(homedir(), ".cache"), "chainwatch");
}

/**
 * Local copy of OSV answers. A missing, unreadable or invalid file is an empty cache: a bad
 * cache can only cost a network lookup, never produce a "clean" result.
 */
export class AdvisoryCache {
  private queries = new Map<string, { ids: string[]; fetchedAt: string }>();
  private advisories = new Map<string, { advisory: Advisory; fetchedAt: string }>();
  private dirty = false;
  /** True when a cache file existed but could not be used. */
  corrupt = false;

  private constructor(private readonly dir: string) {}

  static async load(dir: string): Promise<AdvisoryCache> {
    const cache = new AdvisoryCache(dir);
    let text: string;
    try {
      text = await readFile(join(dir, CACHE_FILE), "utf8");
    } catch {
      return cache;
    }
    try {
      const parsed = fileSchema.parse(JSON.parse(text));
      cache.queries = new Map(Object.entries(parsed.queries));
      cache.advisories = new Map(Object.entries(parsed.advisories));
    } catch {
      cache.corrupt = true;
    }
    return cache;
  }

  /** An in-memory cache that never touches disk, for --no-cache. */
  static empty(): AdvisoryCache {
    return new AdvisoryCache("");
  }

  getQuery(key: string): CacheEntry<string[]> | undefined {
    const e = this.queries.get(key);
    return e && { value: e.ids, fetchedAt: new Date(e.fetchedAt) };
  }

  setQuery(key: string, ids: string[], now: Date): void {
    this.queries.set(key, { ids, fetchedAt: now.toISOString() });
    this.dirty = true;
  }

  getAdvisory(id: string): CacheEntry<Advisory> | undefined {
    const e = this.advisories.get(id);
    return e && { value: e.advisory, fetchedAt: new Date(e.fetchedAt) };
  }

  setAdvisory(advisory: Advisory, now: Date): void {
    this.advisories.set(advisory.id, { advisory, fetchedAt: now.toISOString() });
    this.dirty = true;
  }

  /** Writes atomically (temp file then rename). Returns false if the cache could not be saved. */
  async save(now: Date): Promise<boolean> {
    if (!this.dir || !this.dirty) return true;
    const cutoff = now.getTime() - MAX_ENTRY_AGE_MS;
    const fresh = <T extends { fetchedAt: string }>(m: Map<string, T>) =>
      Object.fromEntries([...m].filter(([, e]) => Date.parse(e.fetchedAt) >= cutoff));
    const body = JSON.stringify({
      version: 1,
      queries: fresh(this.queries),
      advisories: fresh(this.advisories),
    });
    const file = join(this.dir, CACHE_FILE);
    const tmp = `${file}.${process.pid}.tmp`;
    try {
      await mkdir(dirname(file), { recursive: true });
      await writeFile(tmp, body);
      await rename(tmp, file);
      return true;
    } catch {
      return false;
    }
  }
}
