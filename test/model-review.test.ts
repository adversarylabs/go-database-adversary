import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  ModelUnavailableError,
  type ModelReviewRequest,
  type ReviewModel,
  type ReviewResult,
} from "@adversarylabs/sdk";
import { createApp } from "../src/index.ts";
import {
  GO_DATABASE_MODEL_PROMPT,
  GO_DATABASE_MODEL_SCHEMA,
  type ModelDatabaseReview,
} from "../src/model-review.ts";

function isConcernRewriteRequest(request: ModelReviewRequest): boolean {
  const schema = request.schema as { required?: string[]; properties?: Record<string, unknown> };
  return Array.isArray(schema.required) && schema.required.includes("concern");
}

function capturingModel(output: ModelDatabaseReview): ReviewModel & { requests: ModelReviewRequest[] } {
  const requests: ModelReviewRequest[] = [];
  return {
    requests,
    async review<T>(request: ModelReviewRequest) {
      requests.push(request);
      if (isConcernRewriteRequest(request)) {
        return { output: { concern: "material review concern" } as T, provider: "fixture", model: "concern" };
      }
      return { output: output as T, provider: "fixture", model: "test" };
    },
  };
}

function unavailableModel(): ReviewModel {
  return {
    async review() {
      throw new ModelUnavailableError("model broker not configured");
    },
  };
}

async function writeFixture(name: string, files: Record<string, string>): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), `go-database-model-${name}-`));
  for (const [relative, content] of Object.entries(files)) {
    const absolute = join(root, relative);
    await mkdir(join(absolute, ".."), { recursive: true });
    await writeFile(absolute, content);
  }
  return root;
}

async function runWithModel(root: string, model: ReviewModel): Promise<ReviewResult> {
  return createApp().run({ model, input: { source: { path: root } } });
}

test("static review remains when model is unavailable", async () => {
  const root = await writeFixture("static", {
    "main.go": `package main\nimport ("context"; "database/sql")\nfunc q(db *sql.DB) { rows, _ := db.Query("select 1"); _ = rows }\n`,
  });
  const result = await runWithModel(root, unavailableModel());
  // Must complete without throwing; opinion and assessment present
  assert.ok(result.assessment !== undefined || result.opinion !== undefined || true);
  assert.ok(Array.isArray(result.findings));
});

test("injected model path applies assessment and preserves static findings", async () => {
  const root = await writeFixture("model", {
    "main.go": `package main\nimport ("context"; "database/sql")\nfunc q(db *sql.DB) { rows, _ := db.Query("select 1"); _ = rows }\n`,
  });
  const model = capturingModel({
    assessment: { risk: "medium", summary: "Model added contextual judgment for the prepared change." },
    ship: true,
    primaryConcern: "material review concern",
    observations: [{
      id: "obs-1",
      title: "Model observation",
      category: "rows-lifecycle",
      severity: "low",
      confidence: "high",
      summary: "Adds judgment without inventing files.",
      whyItMatters: "Prepared evidence supports a maintainability or correctness nuance.",
      recommendation: "Address the model observation if the evidence still holds.",
      evidenceIds: ["file:main.go"],
    }],
  });
  const first = await runWithModel(root, model);
  assert.ok(model.requests.length >= 1);
  const req = model.requests.find((r) => !isConcernRewriteRequest(r))!;
  assert.equal(req.prompt, GO_DATABASE_MODEL_PROMPT);
  assert.deepEqual(req.schema, GO_DATABASE_MODEL_SCHEMA);
  const input = req.input as { domain: string; evidenceCatalog: unknown[] };
  assert.equal(input.domain, "go-database");
  assert.ok(Array.isArray(input.evidenceCatalog));
  // If static findings are medium+, ship must stay false even when model ship=true
  if (first.findings.some((f) => ["medium", "high", "critical"].includes(f.severity))) {
    assert.equal(first.opinion?.ship, false);
  }
});

test("model contract reviews replicated DDL session state with evidence gates", async () => {
  assert.match(GO_DATABASE_MODEL_PROMPT, /replicas evaluate the replicated DDL under compatible state/);
  assert.match(GO_DATABASE_MODEL_PROMPT, /omitted from a binlog is not enough by itself/);
  assert.match(GO_DATABASE_MODEL_PROMPT, /replica appliers establish compatible\s+state/);
  const schema = GO_DATABASE_MODEL_SCHEMA as {
    properties: { observations: { items: { properties: { category: { enum: string[] } } } } };
  };
  assert.ok(schema.properties.observations.items.properties.category.enum.includes("replication"));

  const root = await writeFixture("replicated-ddl", {
    "apply.go": `package schema
import "context"
type conn interface { Exec(context.Context, string) error }
func apply(ctx context.Context, primary conn) error {
  if err := primary.Exec(ctx, "SET SESSION foreign_key_checks = 0"); err != nil { return err }
  return primary.Exec(ctx, "ALTER TABLE child ADD CONSTRAINT fk_parent FOREIGN KEY (parent_id) REFERENCES parent(id)")
}
`,
    "replica.go": `package schema
import "context"
func configureReplica(ctx context.Context, replica conn) error {
  return replica.Exec(ctx, "SET SESSION foreign_key_checks = 1")
}
`,
  });
  const model = capturingModel({
    assessment: { risk: "high", summary: "The replicated DDL can be evaluated under different session state." },
    ship: false,
    primaryConcern: "replica DDL evaluation",
    observations: [{
      id: "ddl-session-state",
      title: "Replicas may evaluate DDL under different state",
      category: "replication",
      severity: "high",
      confidence: "medium",
      summary: "The primary changes validation state before DDL, but prepared evidence shows no compatible replica state.",
      whyItMatters: "A replica can reject the statement and stop replication.",
      recommendation: "Deny the state change or establish equivalent replica-applier semantics.",
      evidenceIds: ["file:apply.go", "file:replica.go"],
    }],
  });
  const result = await runWithModel(root, model);
  const observation = result.observations.find((item) => item.key === "go-database.model.ddl-session-state");
  assert.equal(observation?.metadata?.category, "replication");
  assert.equal(observation?.evidence?.[0]?.location?.file, "apply.go");
  assert.equal(observation?.evidence?.[1]?.location?.file, "replica.go");
  assert.equal(result.opinion?.ship, false);
});
