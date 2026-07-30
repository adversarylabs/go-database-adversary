import assert from "node:assert/strict";
import { cp, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { createApp } from "../src/index.ts";
const root = dirname(dirname(fileURLToPath(import.meta.url)));
async function iso(rel: string) {
  const d = await mkdtemp(join(tmpdir(), "go-db-p0-"));
  await cp(join(root, "fixtures", rel), d, { recursive: true });
  return d;
}
const review = async (rel: string) => createApp().run({ input: { source: { path: await iso(rel) } } });
test("P0 go-database rules", async () => {
  for (const c of [
    { dir: "p0-sqli", id: "go-database.sql-injection" },
    { dir: "p0-dsnlog", id: "go-database.dsn-logging" },
    { dir: "p0-dsnpw", id: "go-database.inline-dsn-password" },
  ] as const) {
    const bad = await review(`${c.dir}/vulnerable`);
    assert.equal(bad.findings.some((f) => f.ruleId === c.id || f.ruleId?.includes("transaction") || f.ruleId?.includes("rows")), true, `${c.id} ${bad.findings.map(f=>f.ruleId)}`);
    // for sql/dsn require exact id
    if (c.id.includes("sql") || c.id.includes("dsn") || c.id.includes("inline")) {
      assert.equal(bad.findings.some((f) => f.ruleId === c.id), true, `exact ${c.id}`);
    }
    const good = await review(`${c.dir}/clean`);
    assert.equal(good.findings.some((f) => f.ruleId === c.id), false);
  }
});
// also ensure existing lifecycle rules still work via existing tests
