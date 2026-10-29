import { describe, expect, it } from "vitest";
import { OsvClient } from "../../src/advisories/osv-client";
import type { PackageId } from "../../src/core/types";
import { loadVuln } from "../helpers/fixture-provider";

const pkg = (name: string, version = "1.0.0"): PackageId => ({ ecosystem: "npm", name, version });
const json = (body: unknown, init?: ResponseInit) =>
  new Response(JSON.stringify(body), { status: 200, ...init });

type Handler = (url: string, init: RequestInit) => Response | Promise<Response>;

function client(handler: Handler, options: ConstructorParameters<typeof OsvClient>[0] = {}) {
  const calls: { url: string; body: unknown }[] = [];
  const sleeps: number[] = [];
  const instance = new OsvClient({
    baseUrl: "https://osv.test",
    fetch: (async (url: string, init: RequestInit) => {
      calls.push({ url, body: init.body ? JSON.parse(init.body as string) : undefined });
      return handler(url, init);
    }) as typeof fetch,
    sleep: async (ms) => {
      sleeps.push(ms);
    },
    ...options,
  });
  return { instance, calls, sleeps };
}

describe("OsvClient.queryBatch", () => {
  it("sends one query per package and returns the advisory ids", async () => {
    const { instance, calls } = client(() =>
      json({ results: [{ vulns: [{ id: "GHSA-b" }, { id: "GHSA-a" }] }, {}] }),
    );
    const result = await instance.queryBatch([pkg("a"), pkg("b", "2.0.0")]);
    expect(result.get("a@1.0.0")).toEqual({ ok: true, value: ["GHSA-a", "GHSA-b"] });
    expect(result.get("b@2.0.0")).toEqual({ ok: true, value: [] });
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe("https://osv.test/v1/querybatch");
    expect(calls[0]?.body).toEqual({
      queries: [
        { package: { name: "a", ecosystem: "npm" }, version: "1.0.0" },
        { package: { name: "b", ecosystem: "npm" }, version: "2.0.0" },
      ],
    });
  });

  it("splits large inputs into several requests", async () => {
    const { instance, calls } = client(
      (_url, init) => {
        const n = (JSON.parse(init.body as string) as { queries: unknown[] }).queries.length;
        return json({ results: Array.from({ length: n }, () => ({})) });
      },
      { batchSize: 2 },
    );
    const result = await instance.queryBatch(["a", "b", "c", "d", "e"].map((n) => pkg(n)));
    expect(calls).toHaveLength(3);
    expect(result.size).toBe(5);
  });

  it("de-duplicates identical packages", async () => {
    const { instance, calls } = client(() => json({ results: [{}] }));
    await instance.queryBatch([pkg("a"), pkg("a")]);
    expect((calls[0]?.body as { queries: unknown[] }).queries).toHaveLength(1);
  });

  it("follows next_page_token until the results are complete", async () => {
    const { instance, calls } = client((_url, init) => {
      const q = (JSON.parse(init.body as string) as { queries: { page_token?: string }[] })
        .queries[0];
      return q?.page_token === "t1"
        ? json({ results: [{ vulns: [{ id: "GHSA-2" }] }] })
        : json({ results: [{ vulns: [{ id: "GHSA-1" }], next_page_token: "t1" }] });
    });
    const result = await instance.queryBatch([pkg("a")]);
    expect(result.get("a@1.0.0")).toEqual({ ok: true, value: ["GHSA-1", "GHSA-2"] });
    expect(calls).toHaveLength(2);
  });

  it("retries transient server errors and then succeeds", async () => {
    let n = 0;
    const { instance, calls, sleeps } = client(() =>
      ++n < 3
        ? new Response("busy", { status: 503 })
        : json({ results: [{ vulns: [{ id: "GHSA-1" }] }] }),
    );
    const result = await instance.queryBatch([pkg("a")]);
    expect(result.get("a@1.0.0")).toEqual({ ok: true, value: ["GHSA-1"] });
    expect(calls).toHaveLength(3);
    expect(sleeps).toHaveLength(2);
  });

  it("honors Retry-After on rate limits", async () => {
    let n = 0;
    const { instance, sleeps } = client(() =>
      ++n === 1
        ? new Response("slow down", { status: 429, headers: { "retry-after": "2" } })
        : json({ results: [{}] }),
    );
    await instance.queryBatch([pkg("a")]);
    expect(sleeps).toEqual([2000]);
  });

  it("gives up after the retry limit and reports a failure, not an empty result", async () => {
    const { instance, calls } = client(() => new Response("down", { status: 500 }), {
      maxRetries: 2,
    });
    const result = await instance.queryBatch([pkg("a"), pkg("b")]);
    expect(calls).toHaveLength(3);
    const a = result.get("a@1.0.0");
    expect(a?.ok).toBe(false);
    expect(a && !a.ok && a.error).toMatch(/HTTP 500 after 3 attempts/);
    expect(result.get("b@1.0.0")?.ok).toBe(false);
  });

  it("does not retry client errors", async () => {
    const { instance, calls } = client(() => new Response("bad", { status: 400 }));
    const result = await instance.queryBatch([pkg("a")]);
    expect(calls).toHaveLength(1);
    expect(result.get("a@1.0.0")?.ok).toBe(false);
  });

  it("treats network errors as failures after retrying", async () => {
    const { instance, calls } = client(
      () => {
        throw new TypeError("fetch failed");
      },
      { maxRetries: 1 },
    );
    const result = await instance.queryBatch([pkg("a")]);
    expect(calls).toHaveLength(2);
    const a = result.get("a@1.0.0");
    expect(a && !a.ok && a.error).toMatch(/could not reach OSV/);
  });

  it("fails every package in a batch when the response is malformed", async () => {
    for (const bad of [
      json({ unexpected: true }),
      json({ results: [] }),
      new Response("not json", { status: 200 }),
    ]) {
      const { instance } = client(() => bad.clone());
      const result = await instance.queryBatch([pkg("a")]);
      expect(result.get("a@1.0.0")?.ok).toBe(false);
    }
  });

  it("keeps good batches when another batch fails", async () => {
    let n = 0;
    const { instance } = client(
      () =>
        ++n === 1
          ? json({ results: [{ vulns: [{ id: "GHSA-1" }] }] })
          : new Response("no", { status: 400 }),
      { batchSize: 1, concurrency: 1 },
    );
    const result = await instance.queryBatch([pkg("a"), pkg("b")]);
    expect(result.get("a@1.0.0")).toEqual({ ok: true, value: ["GHSA-1"] });
    expect(result.get("b@1.0.0")?.ok).toBe(false);
  });
});

describe("OsvClient.getAdvisories", () => {
  it("fetches and normalizes each record", async () => {
    const { instance, calls } = client((url) =>
      json(loadVuln(decodeURIComponent(url.split("/").pop() as string))),
    );
    const result = await instance.getAdvisories(["GHSA-35jh-r3h4-6jhm", "GHSA-35jh-r3h4-6jhm"]);
    expect(calls).toHaveLength(1);
    const lookup = result.get("GHSA-35jh-r3h4-6jhm");
    expect(lookup?.ok && lookup.value.severity.label).toBe("HIGH");
  });

  it("reports a failure per id and encodes ids in the URL", async () => {
    const { instance, calls } = client(() => new Response("missing", { status: 404 }));
    const result = await instance.getAdvisories(["A/B"]);
    expect(calls[0]?.url).toBe("https://osv.test/v1/vulns/A%2FB");
    expect(result.get("A/B")?.ok).toBe(false);
  });
});
