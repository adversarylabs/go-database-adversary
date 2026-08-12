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

test("Next loop without Err check reports silent row truncation", async () => {
  const root = await mkdtemp(join(tmpdir(), "go-db-rows-err-"));
  await writeFile(
    join(root, "main.go"),
    `package main

import (
	"context"
	"database/sql"
)

func load(ctx context.Context, db *sql.DB) ([]int, error) {
	rows, err := db.QueryContext(ctx, "select id from jobs")
	if err != nil { return nil, err }
	defer rows.Close()
	var ids []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil { return nil, err }
		ids = append(ids, id)
	}
	return ids, nil
}
`,
  );
  const output = await createApp().run({ input: { source: { path: root } }, includeRawObservations: true });
  const finding = output.findings.find((f) => f.ruleId === "go-database.rows-iteration-error");
  assert.ok(finding, `expected rows-iteration-error, got ${JSON.stringify(output.findings, null, 2)}`);
  assert.equal(finding.severity, "high");
});

test("explicit Err check and escaped rows ownership stay clean", async () => {
  const root = await mkdtemp(join(tmpdir(), "go-db-rows-err-ok-"));
  await writeFile(
    join(root, "main.go"),
    `package main

import (
	"context"
	"database/sql"
)

func load(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, "select id from jobs")
	if err != nil { return err }
	defer rows.Close()
	for rows.Next() {}
	return rows.Err()
}

func handOff(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, "select id from jobs")
	if err != nil { return err }
	consume(rows)
	for rows.Next() {}
	return nil
}

func consume(*sql.Rows) {}
`,
  );
  const output = await createApp().run({ input: { source: { path: root } }, includeRawObservations: true });
  assert.equal(output.findings.some((f) => f.ruleId === "go-database.rows-iteration-error"), false);
});

test("Err observed before iteration does not replace the final Err check", async () => {
  const root = await mkdtemp(join(tmpdir(), "go-db-rows-err-order-"));
  await writeFile(
    join(root, "main.go"),
    `package main

import "database/sql"

func load(db *sql.DB) error {
	rows, err := db.Query("select id from jobs")
	if err != nil { return err }
	defer rows.Close()
	_ = rows.Err()
	for rows.Next() {}
	return nil
}
`,
  );
  const output = await createApp().run({ input: { source: { path: root } }, includeRawObservations: true });
  assert.ok(output.findings.some((f) => f.ruleId === "go-database.rows-iteration-error"));
});

test("Go code inside quoted literals does not report row iteration errors", async () => {
  const root = await mkdtemp(join(tmpdir(), "go-db-rows-err-strings-"));
  await writeFile(
    join(root, "main.go"),
    `package main

import "database/sql"

var _ *sql.DB

const rawExample = \`rows, err := db.QueryContext(ctx, "select 1")
for rows.Next() {}
return nil\`

const quotedExample = "rows, err := db.QueryContext(ctx, query) for rows.Next() {} return nil"
`,
  );
  const output = await createApp().run({ input: { source: { path: root } }, includeRawObservations: true });
  assert.equal(output.findings.some((f) => f.ruleId === "go-database.rows-iteration-error"), false);
});

test("real row iteration still reports beside code-looking strings", async () => {
  const root = await mkdtemp(join(tmpdir(), "go-db-rows-err-real-"));
  await writeFile(
    join(root, "main.go"),
    `package main

import "database/sql"

const example = \`rows, err := db.Query("select example")
for rows.Next() {}\`

func load(db *sql.DB) error {
	rows, err := db.Query("select id from jobs")
	if err != nil { return err }
	defer rows.Close()
	for rows.Next() {}
	return nil
}
`,
  );
  const output = await createApp().run({ input: { source: { path: root } }, includeRawObservations: true });
  assert.equal(output.findings.filter((f) => f.ruleId === "go-database.rows-iteration-error").length, 1);
});
