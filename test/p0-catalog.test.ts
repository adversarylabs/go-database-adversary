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

const review = async (rel: string) =>
  createApp().run({ input: { source: { path: await iso(rel) } }, includeRawObservations: true });

test("P0 go-database rules detect vulnerable fixtures and stay quiet on clean", async () => {
  const cases = [
    { dir: "p0-sqli", id: "go-database.sql-injection" },
    { dir: "p0-gorm-raw", id: "go-database.gorm-raw" },
    { dir: "p0-dsnlog", id: "go-database.dsn-logging" },
    { dir: "p0-dsnpw", id: "go-database.inline-dsn-password" },
  ] as const;
  for (const c of cases) {
    const bad = await review(`${c.dir}/vulnerable`);
    assert.equal(
      bad.findings.some((f) => f.ruleId === c.id),
      true,
      `${c.id} missed on vulnerable; got ${bad.findings.map((f) => f.ruleId).join(",")}`,
    );
    const good = await review(`${c.dir}/clean`);
    assert.equal(
      good.findings.some((f) => f.ruleId === c.id),
      false,
      `${c.id} flagged clean; got ${good.findings.map((f) => f.ruleId).join(",")}`,
    );
  }
});
