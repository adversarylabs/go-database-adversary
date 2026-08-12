import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { cp, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import test from "node:test";
import { type ReviewResult } from "@adversarylabs/sdk";
import { createApp } from "../src/index.ts";

const projectRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const execute = promisify(execFile);

async function review(root: string): Promise<ReviewResult> {
  return createApp().run({ input: { source: { path: root } }, includeRawObservations: true });
}

function snapshot(output: ReviewResult) {
  return {
    risk: output.assessment?.risk,
    findings: output.findings.map((finding) => ({
      ruleId: finding.ruleId,
      severity: finding.severity,
      evidenceCount: finding.evidence.length,
    })),
    positiveKeys: output.positives.map((item) => item.key),
    ship: output.opinion?.ship,
  };
}

for (const grade of ["excellent", "good", "average", "poor", "terrible"]) {
  test(`${grade} fixture matches its expected review snapshot`, async () => {
    const fixture = join(projectRoot, "fixtures", grade);
    const root = await isolatedFixture(fixture);
    const expected = JSON.parse(await readFile(join(fixture, "expected.review.json"), "utf8"));
    assert.deepEqual(snapshot(await review(root)), expected);
  });
}

test("review output is deterministic", async () => {
  const root = await isolatedFixture(join(projectRoot, "fixtures", "terrible"));
  assert.deepEqual(await review(root), await review(root));
});

test("an unrelated edit does not surface a legacy rows iteration finding", async () => {
  const legacySource = `package main

import "database/sql"

func load(db *sql.DB) error {
	rows, err := db.Query("select id from jobs")
	if err != nil { return err }
	defer rows.Close()
	for rows.Next() {}
	return nil
}
`;
  const root = await gitRepository({ "main.go": legacySource });
  await writeFile(join(root, "main.go"), `${legacySource}\n// unrelated documentation update\n`);

  const output = await changedReview(root, ["main.go"]);
  assert.equal(
    output.findings.some((finding) => finding.ruleId === "go-database.rows-iteration-error"),
    false,
  );
});

test("a newly added source still reports a rows iteration finding", async () => {
  const root = await gitRepository({ "README.md": "# service\n" });
  await writeFile(
    join(root, "main.go"),
    `package main

import "database/sql"

func load(db *sql.DB) error {
	rows, err := db.Query("select id from jobs")
	if err != nil { return err }
	defer rows.Close()
	for rows.Next() {}
	return nil
}
`,
  );

  const output = await changedReview(root, ["main.go"]);
  assert.equal(
    output.findings.some((finding) => finding.ruleId === "go-database.rows-iteration-error"),
    true,
  );
});

async function isolatedFixture(fixture: string): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "go-domain-fixture-"));
  await cp(fixture, root, { recursive: true });
  return root;
}

async function changedReview(root: string, changedFiles: string[]): Promise<ReviewResult> {
  return createApp().run({
    input: {
      source: { path: root },
      change: {
        type: "diff",
        base_ref: "HEAD",
        head_ref: "WORKTREE",
        scan_mode: "changed",
        changed_files: changedFiles,
      },
    },
    includeRawObservations: true,
  });
}

async function gitRepository(files: Record<string, string>): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "go-database-git-"));
  await execute("git", ["init", "--quiet", root]);
  await execute("git", ["-C", root, "config", "user.email", "tests@example.com"]);
  await execute("git", ["-C", root, "config", "user.name", "Tests"]);
  for (const [path, content] of Object.entries(files)) {
    await writeFile(join(root, path), content);
  }
  await execute("git", ["-C", root, "add", "."]);
  await execute("git", ["-C", root, "commit", "--quiet", "-m", "baseline"]);
  return root;
}
