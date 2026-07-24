import { contentSignal, lineSignals, positive } from "./signals.js";
import { type DomainDefinition } from "./types.js";

export const domain: DomainDefinition = {
  name: "go-database",
  displayName: "Go Database",
  observationKey: "go-database.analysis",
  sourceDescription: "Go database",
  includePath: (path) => path.endsWith(".go") || /\.(?:sql|up\.sql|down\.sql)$/.test(path),
  rules: [
    {
      id: "go-database.rows-lifecycle",
      title: "Query rows are not closed by their owner",
      category: "reliability",
      severity: "high",
      confidence: "high",
      summary: (count) => `${count} query result${count === 1 ? "" : "s"} have no matching Close lifecycle.`,
      whyItMatters: "Rows retain a database connection until closed or fully consumed.",
      impact: "Early returns and scan failures can exhaust the pool and stall unrelated requests.",
      recommendation: "Check the query error and immediately defer rows.Close in the same owning scope.",
    },
    {
      id: "go-database.transaction-lifecycle",
      title: "A transaction has no rollback safety net",
      category: "correctness",
      severity: "high",
      confidence: "high",
      summary: (count) => `${count} transaction start${count === 1 ? "" : "s"} lack an immediate deferred rollback.`,
      whyItMatters: "Every return path before a successful commit must release the transaction and connection.",
      impact: "Errors can leave transactions open, retain locks, and exhaust the connection pool.",
      recommendation: "Defer Rollback immediately after Begin succeeds; treat the expected post-Commit rollback error as harmless.",
    },
    {
      id: "go-database.contextless-query",
      title: "Database work cannot observe caller cancellation",
      category: "reliability",
      severity: "medium",
      confidence: "high",
      summary: (count) => `${count} database operation${count === 1 ? "" : "s"} use a contextless query API.`,
      whyItMatters: "Request, command, and worker cancellation must reach network waits and server-side query execution.",
      impact: "Timed-out work can continue consuming connections and database capacity.",
      recommendation: "Use QueryContext, ExecContext, or the library's context-aware equivalent with the owning context.",
    },
  ],
  noRiskSummary: "The reviewed database code has explicit row, transaction, and cancellation ownership.",
  approvalSummary: "I would approve the reviewed database lifecycle and transaction behavior.",
  analyze(file) {
    if (!file.path.endsWith(".go")) return { signals: [], positives: [] };
    const rows = /\brows\s*,\s*err\s*:=\s*\w+\.QueryContext\s*\(/.test(file.current) && !/defer\s+rows\.Close\s*\(\)/.test(file.current)
      ? contentSignal(file, "go-database.rows-lifecycle", /\brows\s*,\s*err\s*:=\s*\w+\.QueryContext\s*\(/, "The rows owner does not defer rows.Close.")
      : [];
    const tx = /\btx\s*,\s*err\s*:=\s*\w+\.Begin(?:Tx)?\s*\(/.test(file.current) && !/defer\s+tx\.Rollback\s*\(\)/.test(file.current)
      ? contentSignal(file, "go-database.transaction-lifecycle", /\btx\s*,\s*err\s*:=\s*\w+\.Begin(?:Tx)?\s*\(/, "The transaction owner has no deferred rollback.")
      : [];
    return {
      signals: [
        ...rows,
        ...tx,
        ...lineSignals(file, "go-database.contextless-query", /\.(?:Query|Exec)\s*\(/, () => "This database operation has no cancellation context."),
      ],
      positives: [
        ...positive(file, "go-database.rows-owned", /defer\s+rows\.Close\s*\(\)/, "Query rows are closed by their owning scope."),
        ...positive(file, "go-database.rollback-owned", /defer\s+tx\.Rollback\s*\(\)/, "The transaction has rollback coverage for every early return."),
      ],
    };
  },
};
