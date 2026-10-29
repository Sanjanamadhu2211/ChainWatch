// Captures real OSV responses for the fixture lockfiles so tests can replay them offline.
// Usage: node scripts/capture-osv-fixtures.mjs
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const out = join(root, "tests", "fixtures", "osv");
mkdirSync(join(out, "vulns"), { recursive: true });

const seen = new Map();
for (const dir of ["vulnerable", "patched"]) {
  const lock = JSON.parse(
    readFileSync(join(root, "tests", "fixtures", dir, "package-lock.json"), "utf8"),
  );
  for (const [key, e] of Object.entries(lock.packages)) {
    if (key && e.version && !e.link)
      seen.set(`${e.name ?? key.split("node_modules/").pop()}@${e.version}`, true);
  }
}
const queries = [...seen.keys()].sort().map((k) => {
  const at = k.lastIndexOf("@");
  return { package: { name: k.slice(0, at), ecosystem: "npm" }, version: k.slice(at + 1) };
});
const res = await (
  await fetch("https://api.osv.dev/v1/querybatch", {
    method: "POST",
    body: JSON.stringify({ queries }),
  })
).json();
const byKey = {};
const ids = new Set();
res.results.forEach((r, i) => {
  const q = queries[i];
  byKey[`${q.package.name}@${q.version}`] = (r.vulns ?? []).map((v) => v.id);
  (r.vulns ?? []).forEach((v) => ids.add(v.id));
});
writeFileSync(join(out, "queries.json"), JSON.stringify(byKey, null, 2) + "\n");
for (const id of ids) {
  const vuln = await (await fetch(`https://api.osv.dev/v1/vulns/${id}`)).json();
  writeFileSync(join(out, "vulns", `${id}.json`), JSON.stringify(vuln, null, 2) + "\n");
}
console.log(`captured ${Object.keys(byKey).length} packages, ${ids.size} advisories`);
