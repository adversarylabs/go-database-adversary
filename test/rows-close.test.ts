import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createApp } from "../src/index.ts";
import { hasDeferredRowsClose } from "../src/domain.ts";

test("hasDeferredRowsClose recognizes common defer patterns", () => {
  const withDefer = `func f() {
	rows, err := db.QueryContext(ctx, "select 1")
	if err != nil { return }
	defer rows.Close()
}`;
  assert.equal(hasDeferredRowsClose(withDefer, withDefer.indexOf("rows,"), "rows"), true);

  const nilGuard = `func f() {
	rows, err := db.Query("select 1")
	if rows != nil {
		defer rows.Close()
	}
}`;
  assert.equal(hasDeferredRowsClose(nilGuard, nilGuard.indexOf("rows,"), "rows"), true);

  const missing = `func f() {
	rows, err := db.QueryContext(ctx, "select 1")
	_ = rows
	return err
}`;
  assert.equal(hasDeferredRowsClose(missing, missing.indexOf("rows,"), "rows"), false);
});

test("forgets defer Close on QueryContext is critical rows-lifecycle", async () => {
  const root = await mkdtemp(join(tmpdir(), "go-db-rows-"));
  await writeFile(
    join(root, "main.go"),
    `package main

import (
	"context"
	"database/sql"
)

func load(ctx context.Context, db *sql.DB) error {
	result, err := db.QueryContext(ctx, "select id from jobs")
	if err != nil {
		return err
	}
	// forgot: defer result.Close()
	for result.Next() {
	}
	return result.Err()
}
`,
  );
  const output = await createApp().run({ input: { source: { path: root } }, includeRawObservations: true });
  const finding = output.findings.find((f) => f.ruleId === "go-database.rows-lifecycle");
  assert.ok(finding, `expected rows-lifecycle, got ${JSON.stringify(output.findings, null, 2)}`);
  assert.equal(finding.severity, "critical");
});

test("plain Query without Close is critical", async () => {
  const root = await mkdtemp(join(tmpdir(), "go-db-rows-q-"));
  await writeFile(
    join(root, "main.go"),
    `package main

import "database/sql"

func load(db *sql.DB) error {
	rs, err := db.Query("select id from jobs")
	_ = rs
	return err
}
`,
  );
  const output = await createApp().run({ input: { source: { path: root } }, includeRawObservations: true });
  assert.ok(output.findings.some((f) => f.ruleId === "go-database.rows-lifecycle" && f.severity === "critical"));
});

test("defer Close after Query is clean for rows-lifecycle", async () => {
  const root = await mkdtemp(join(tmpdir(), "go-db-rows-ok-"));
  await writeFile(
    join(root, "main.go"),
    `package main

import (
	"context"
	"database/sql"
)

func load(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, "select id from jobs")
	if err != nil {
		return err
	}
	defer rows.Close()
	return nil
}
`,
  );
  const output = await createApp().run({ input: { source: { path: root } }, includeRawObservations: true });
  assert.equal(output.findings.some((f) => f.ruleId === "go-database.rows-lifecycle"), false);
});
