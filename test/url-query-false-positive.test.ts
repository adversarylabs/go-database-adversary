import assert from "node:assert/strict";
import { mkdtemp, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createApp } from "../src/index.ts";
import { isLikelyDatabaseQueryOrExec } from "../src/domain.ts";

test("URL.Query and Query().Get are not database operations", () => {
  assert.equal(isLikelyDatabaseQueryOrExec(`v := r.URL.Query().Get("nonce")`), false);
  assert.equal(isLikelyDatabaseQueryOrExec(`for k, v := range req.URL.Query() {`), false);
  assert.equal(isLikelyDatabaseQueryOrExec(`q := r.URL.Query()`), false);
  assert.equal(
    isLikelyDatabaseQueryOrExec(
      `rows, err := db.Query("select 1")`,
      `import "database/sql"\n`,
    ),
    true,
  );
  assert.equal(
    isLikelyDatabaseQueryOrExec(`_, err := tx.Exec("update t set x=1")`, `import "database/sql"\n`),
    true,
  );
});

test("HTTP URL query fixtures do not emit go-database.contextless-query", async () => {
  const root = await mkdtemp(join(tmpdir(), "go-db-url-"));
  await mkdir(join(root, "pkg"), { recursive: true });
  await writeFile(
    join(root, "pkg", "handler.go"),
    `package pkg

import "net/http"

func fetch(r *http.Request) string {
	return r.URL.Query().Get("nonce")
}

func search(r *http.Request) {
	_ = r.URL.Query().Get("search")
	for k := range r.URL.Query() {
		_ = k
	}
}
`,
  );
  const output = await createApp().run({ input: { source: { path: root } }, includeRawObservations: true });
  assert.equal(
    output.findings.some((f) => f.ruleId === "go-database.contextless-query"),
    false,
    `unexpected findings: ${JSON.stringify(output.findings, null, 2)}`,
  );
});

test("real database/sql Query still flags contextless-query", async () => {
  const root = await mkdtemp(join(tmpdir(), "go-db-sql-"));
  await writeFile(
    join(root, "main.go"),
    `package main

import "database/sql"

func load(db *sql.DB) error {
	rows, err := db.Query("select 1")
	_ = rows
	return err
}
`,
  );
  const output = await createApp().run({ input: { source: { path: root } }, includeRawObservations: true });
  assert.equal(
    output.findings.some((f) => f.ruleId === "go-database.contextless-query"),
    true,
    `expected contextless-query, got ${JSON.stringify(output.findings, null, 2)}`,
  );
});
