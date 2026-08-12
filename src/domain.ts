import { contentSignal, lineSignals, positive } from "./signals.js";
import { type DomainDefinition, type SourceRevision } from "./types.js";

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
      concern: "unclosed database query rows",
      category: "reliability",
      severity: "critical",
      confidence: "high",
      summary: (count) =>
        `${count} multi-row query result${count === 1 ? "" : "s"} (*sql.Rows) have no deferred Close in the owning scope.`,
      whyItMatters:
        "Query/QueryContext return *sql.Rows that hold a pool connection until Close; forgetting defer Close is a classic connection-pool leak.",
      impact:
        "Early returns, scan errors, and forgotten Close exhaust the connection pool and stall the whole process under load.",
      recommendation:
        "After a successful Query/QueryContext, immediately `defer rows.Close()` (or close that variable) in the same function before scanning.",
    },
    {
      id: "go-database.transaction-lifecycle",
      title: "A transaction has no rollback safety net",
      concern: "transactions without deferred rollback",
      category: "correctness",
      severity: "high",
      confidence: "high",
      summary: (count) => `${count} transaction start${count === 1 ? "" : "s"} lack an immediate deferred rollback.`,
      whyItMatters: "Every return path before a successful commit must release the transaction and connection.",
      impact: "Errors can leave transactions open, retain locks, and exhaust the connection pool.",
      recommendation: "Defer Rollback immediately after Begin succeeds; treat the expected post-Commit rollback error as harmless.",
    },
    {
      id: "go-database.rows-iteration-error",
      title: "Row iteration errors are discarded",
      concern: "unchecked database row iteration errors",
      category: "correctness",
      severity: "high",
      confidence: "high",
      summary: (count) =>
        `${count} multi-row query loop${count === 1 ? " does" : "s do"} not check the row iterator's final error.`,
      whyItMatters:
        "Next stops for both normal exhaustion and driver errors; only Err distinguishes a complete result from a truncated one.",
      impact: "Callers can accept incomplete query results as complete and make decisions from silently missing rows.",
      recommendation: "After the Next loop, check and return or otherwise handle `rows.Err()`.",
    },
    {
      id: "go-database.contextless-query",
      title: "Database work cannot observe caller cancellation",
      concern: "contextless database operations",
      category: "reliability",
      severity: "medium",
      confidence: "high",
      summary: (count) => `${count} database operation${count === 1 ? "" : "s"} use a contextless query API.`,
      whyItMatters: "Request, command, and worker cancellation must reach network waits and server-side query execution.",
      impact: "Timed-out work can continue consuming connections and database capacity.",
      recommendation: "Use QueryContext, ExecContext, or the library's context-aware equivalent with the owning context.",
    },

    {
      id: "go-database.sql-injection",
      title: "SQL built with string formatting",
      concern: "SQL injection",
      category: "security",
      severity: "critical",
      confidence: "high",
      summary: (count) => `${count} SQL construction${count === 1 ? "" : "s"} use string formatting.`,
      whyItMatters: "User-controlled SQL fragments enable injection.",
      impact: "Database compromise.",
      recommendation: "Use bound parameters only.",
    },
    {
      id: "go-database.dsn-logging",
      title: "Database DSN or password is logged",
      concern: "credential logging",
      category: "security",
      severity: "high",
      confidence: "high",
      summary: (count) => `${count} log path${count === 1 ? "" : "s"} may emit DSN/password material.`,
      whyItMatters: "Logs retain credentials longer than process memory.",
      impact: "Credential theft from log sinks.",
      recommendation: "Never log DSNs; redact connection strings.",
    },
    {
      id: "go-database.inline-dsn-password",
      title: "Hardcoded password in DSN",
      concern: "hardcoded DSN password",
      category: "security",
      severity: "critical",
      confidence: "high",
      summary: (count) => `${count} DSN literal${count === 1 ? "" : "s"} embed passwords.`,
      whyItMatters: "Embedded DB passwords are extractable secrets.",
      impact: "Database credential exposure.",
      recommendation: "Load passwords from the environment or a secret manager.",
    },
    {
      id: "go-database.gorm-raw",
      title: "GORM Raw/Exec builds SQL via concatenation",
      concern: "GORM raw SQL injection",
      category: "security",
      severity: "critical",
      confidence: "high",
      summary: (count) =>
        `${count} GORM Raw/Exec call${count === 1 ? "" : "s"} assemble SQL with string formatting or concatenation.`,
      whyItMatters:
        "GORM Raw and Exec pass SQL through to the driver; concatenation reintroduces classic SQL injection.",
      impact: "Database compromise via attacker-controlled SQL fragments.",
      recommendation: "Use bound parameters: db.Raw(\"… WHERE id = ?\", id) or the expression builder.",
    },
  ],
  noRiskSummary: "The reviewed database code has explicit row, transaction, and cancellation ownership.",
  approvalSummary: "I would approve the reviewed database lifecycle and transaction behavior.",
  analyze(file) {
    if (!file.path.endsWith(".go")) return { signals: [], positives: [] };
    const tx = /\btx\s*,\s*err\s*:=\s*\w+\.Begin(?:Tx)?\s*\(/.test(file.current) && !/defer\s+tx\.Rollback\s*\(\)/.test(file.current)
      ? contentSignal(file, "go-database.transaction-lifecycle", /\btx\s*,\s*err\s*:=\s*\w+\.Begin(?:Tx)?\s*\(/, "The transaction owner has no deferred rollback.")
      : [];
    return {
      signals: [
        ...rowsLifecycleSignals(file),
        ...rowsIterationErrorSignals(file),
        ...tx,
        ...contextlessQuerySignals(file),
        ...lineSignals(file, "go-database.sql-injection", /(?:Query|Exec|QueryContext|ExecContext)\s*\(\s*(?:fmt\.Sprintf|["`].*\+)/, () => "SQL may be built via string formatting."),
        ...gormRawSignals(file),
        ...lineSignals(file, "go-database.dsn-logging", /(?:log|slog|fmt)\.[A-Za-z]+\([^)]*(?:dsn|password|DATABASE_URL)/i, () => "A DSN or password may be logged."),
        ...lineSignals(file, "go-database.inline-dsn-password", /(?:postgres|mysql|mongodb):\/\/[^\s"']+:[^\s"'@${]{3,}@/, () => "A DSN literal embeds a password."),
      ],
      positives: [
        ...positive(
          file,
          "go-database.rows-owned",
          /^\s*defer\s+\w+\.Close\s*\(/,
          "Query rows are closed by their owning scope.",
        ),
        ...positive(file, "go-database.rollback-owned", /defer\s+tx\.Rollback\s*\(\)/, "The transaction has rollback coverage for every early return."),
      ],
    };
  },
};

/**
 * Detect multi-row query results (*sql.Rows / sqlx.Rows / pgx.Rows) without a
 * deferred Close on that variable in the same function.
 *
 * Classic bug: `rows, err := db.Query(...)` / `QueryContext` then scan or return
 * without `defer rows.Close()`. QueryRow is excluded (returns *Row, no Close).
 */
function rowsLifecycleSignals(file: SourceRevision) {
  if (file.path.endsWith("_test.go")) return [];
  const source = file.current;
  // name, err := recv.Query( / QueryContext( / Queryx( / QueryxContext(
  // Also allows blank identifier for err: name, _ := ...
  const assignRe =
    /\b([A-Za-z_]\w*)\s*,\s*(?:err|_)\s*:?=\s*[^\n;]*?\.(?:Query|QueryContext|Queryx|QueryxContext)\s*\(/g;
  const signals: ReturnType<typeof contentSignal> = [];
  let match: RegExpExecArray | null;
  while ((match = assignRe.exec(source)) !== null) {
    const varName = match[1] ?? "";
    if (varName === "" || varName === "_") continue;
    // Skip clear non-DB Query (HTTP) — zero-arg or URL.Query already won't match
    // the multi-arg assign pattern with a receiver method name Query.
    const lineText = source.slice(0, match.index).split("\n").pop() + match[0];
    if (/\.URL\.Query\s*\(/.test(lineText) || /\bQuery\s*\(\s*\)/.test(match[0])) continue;
    if (hasDeferredRowsClose(source, match.index ?? 0, varName)) continue;
    const line = source.slice(0, match.index ?? 0).split("\n").length;
    signals.push({
      ruleId: "go-database.rows-lifecycle",
      path: file.path,
      line,
      message: `Multi-row query result "${varName}" is never defer-closed in this function; the pool connection stays checked out.`,
      snippet: (match[0] ?? "").trim().slice(0, 300),
      data: { variable: varName },
    });
  }
  return signals;
}

/**
 * Detect a local multi-row query result consumed by Next without any Err
 * observation. Stay silent when ownership escapes this function: the callee or
 * caller may be responsible for completing iteration and checking the error.
 */
function rowsIterationErrorSignals(file: SourceRevision) {
  if (file.path.endsWith("_test.go")) return [];
  if (!hasDatabaseImport(file.current)) return [];
  const source = stripGoComments(file.current, true);
  const assignRe =
    /\b([A-Za-z_]\w*)\s*,\s*(?:err|_)\s*:?=\s*[^\n;]*?\.(?:Query|QueryContext|Queryx|QueryxContext)\s*\(/g;
  const signals: ReturnType<typeof contentSignal> = [];
  let match: RegExpExecArray | null;
  while ((match = assignRe.exec(source)) !== null) {
    const varName = match[1] ?? "";
    if (varName === "" || varName === "_") continue;
    const rest = source.slice(match.index + match[0].length);
    const nextFunc = rest.search(/\nfunc(?:\s|\()/);
    const scope = nextFunc === -1 ? rest : rest.slice(0, nextFunc);
    const escaped = varName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const loopRe = new RegExp(`\\bfor\\s+${escaped}\\.Next\\s*\\(\\s*\\)\\s*\\{`);
    const loop = loopRe.exec(scope);
    if (loop === null) continue;
    const openBrace = loop.index + loop[0].lastIndexOf("{");
    const loopEnd = goBlockEnd(scope, openBrace);
    if (new RegExp(`\\b${escaped}\\.Err\\s*\\(`).test(scope.slice(loopEnd))) continue;
    if (rowsOwnershipEscapes(scope, escaped)) continue;

    const loopIndex = match.index + match[0].length + loop.index;
    const line = source.slice(0, loopIndex).split("\n").length;
    signals.push({
      ruleId: "go-database.rows-iteration-error",
      path: file.path,
      line,
      message: `The ${varName}.Next() loop never checks ${varName}.Err(); an iteration failure looks like a complete result.`,
      snippet: source.slice(loopIndex, loopIndex + (loop[0]?.length ?? 0)).trim(),
      data: { variable: varName },
    });
  }
  return signals;
}

function goBlockEnd(source: string, openBrace: number): number {
  let depth = 0;
  let quote: '"' | "'" | "`" | undefined;
  let escaped = false;
  for (let index = openBrace; index < source.length; index += 1) {
    const char = source[index]!;
    if (quote !== undefined) {
      if (quote !== "`" && escaped) {
        escaped = false;
      } else if (quote !== "`" && char === "\\") {
        escaped = true;
      } else if (char === quote) {
        quote = undefined;
      }
      continue;
    }
    if (char === '"' || char === "'" || char === "`") {
      quote = char;
    } else if (char === "{") {
      depth += 1;
    } else if (char === "}" && --depth === 0) {
      return index + 1;
    }
  }
  return source.length;
}

function rowsOwnershipEscapes(scope: string, escapedVarName: string): boolean {
  if (new RegExp(`\\breturn\\s+${escapedVarName}\\b`).test(scope)) return true;
  if (new RegExp(`(?:^|[,;{}\\n])\\s*[A-Za-z]\\w*(?:\\.[A-Za-z_]\\w*)?\\s*:?=\\s*${escapedVarName}\\b(?!\\s*\\.)`, "m").test(scope)) {
    return true;
  }
  return new RegExp(`(?:\\(|,)\\s*${escapedVarName}\\s*(?:,|\\))`).test(scope);
}

/** True when the function scope after the assignment defers Close on varName. */
export function hasDeferredRowsClose(source: string, assignIndex: number, varName: string): boolean {
  const rest = stripGoComments(source.slice(assignIndex));
  // Limit to the current function body (next top-level func or EOF).
  const nextFunc = rest.search(/\nfunc(?:\s|\()/);
  const scope = nextFunc === -1 ? rest : rest.slice(0, nextFunc);
  const escaped = varName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  // defer rows.Close()
  if (new RegExp(`\\bdefer\\s+${escaped}\\.Close\\s*\\(`).test(scope)) return true;
  // defer func() { _ = rows.Close() }()
  if (
    new RegExp(
      `\\bdefer\\s+func\\s*\\([^)]*\\)\\s*\\{[\\s\\S]{0,200}?\\b${escaped}\\.Close\\s*\\(`,
    ).test(scope)
  ) {
    return true;
  }
  // if rows != nil { defer rows.Close() }
  if (
    new RegExp(
      `\\bif\\s+${escaped}\\s*!=\\s*nil\\s*\\{[\\s\\S]{0,80}?\\bdefer\\s+${escaped}\\.Close\\s*\\(`,
    ).test(scope)
  ) {
    return true;
  }
  return false;
}

/**
 * Remove comments while preserving byte offsets and line numbers. Optionally
 * blank quoted literal contents for detectors that search for Go syntax.
 */
export function stripGoComments(source: string, stripStringContents = false): string {
  let out = "";
  let i = 0;
  let inLine = false;
  let inBlock = false;
  let inRaw = false;
  let inInterp = false;
  let inChar = false;
  let escape = false;
  while (i < source.length) {
    const ch = source[i]!;
    const next = source[i + 1];
    if (inLine) {
      if (ch === "\n") {
        inLine = false;
        out += "\n";
      } else {
        out += " ";
      }
      i += 1;
      continue;
    }
    if (inBlock) {
      if (ch === "*" && next === "/") {
        inBlock = false;
        out += "  ";
        i += 2;
        continue;
      }
      out += ch === "\n" ? "\n" : " ";
      i += 1;
      continue;
    }
    if (inRaw) {
      out += stripStringContents ? (ch === "\n" ? "\n" : " ") : ch;
      if (ch === "`") inRaw = false;
      i += 1;
      continue;
    }
    if (inInterp) {
      out += stripStringContents ? (ch === "\n" ? "\n" : " ") : ch;
      if (escape) {
        escape = false;
        i += 1;
        continue;
      }
      if (ch === "\\") {
        escape = true;
        i += 1;
        continue;
      }
      if (ch === '"') inInterp = false;
      i += 1;
      continue;
    }
    if (inChar) {
      out += stripStringContents ? (ch === "\n" ? "\n" : " ") : ch;
      if (escape) {
        escape = false;
        i += 1;
        continue;
      }
      if (ch === "\\") {
        escape = true;
        i += 1;
        continue;
      }
      if (ch === "'") inChar = false;
      i += 1;
      continue;
    }
    if (ch === "/" && next === "/") {
      inLine = true;
      out += "  ";
      i += 2;
      continue;
    }
    if (ch === "/" && next === "*") {
      inBlock = true;
      out += "  ";
      i += 2;
      continue;
    }
    if (ch === "`") {
      inRaw = true;
      out += stripStringContents ? " " : ch;
      i += 1;
      continue;
    }
    if (ch === '"') {
      inInterp = true;
      out += stripStringContents ? " " : ch;
      i += 1;
      continue;
    }
    if (ch === "'") {
      inChar = true;
      out += stripStringContents ? " " : ch;
      i += 1;
      continue;
    }
    out += ch;
    i += 1;
  }
  return out;
}

/**
 * Catalog P0 `gorm.raw`: GORM Raw (and gorm.Exec SQL strings) built with
 * fmt.Sprintf or string concatenation instead of bound parameters.
 * Parameterized forms like Raw("… ?", id) stay quiet.
 */
function gormRawSignals(file: SourceRevision) {
  if (file.path.endsWith("_test.go")) return [];
  const hasGorm =
    /gorm\.io\/gorm|"github\.com\/jinzhu\/gorm"/.test(file.current) ||
    /\b(?:db|tx)\s*\.\s*Raw\s*\(/.test(file.current);
  if (!hasGorm && !/\.Raw\s*\(/.test(file.current)) return [];

  const signals = [
    // db.Raw(fmt.Sprintf(...)) or .Raw("..." + id) or .Raw(`...` + id)
    ...lineSignals(
      file,
      "go-database.gorm-raw",
      /\.Raw\s*\(\s*(?:fmt\.Sprintf|[`"'][^`"']*[`"']\s*\+)/,
      () => "GORM Raw builds SQL via formatting or concatenation.",
    ),
    // multi-arg concat: .Raw("select " + col + " from t") — string lit then +
    ...lineSignals(
      file,
      "go-database.gorm-raw",
      /\.Raw\s*\(\s*fmt\.Sprintf\s*\(/,
      () => "GORM Raw uses fmt.Sprintf for SQL assembly.",
    ),
    // gorm.DB.Exec with concat (same SQLi class; distinct from database/sql when gorm imported)
    ...lineSignals(
      file,
      "go-database.gorm-raw",
      /\.Exec\s*\(\s*(?:fmt\.Sprintf|[`"'][^`"']*[`"']\s*\+)/,
      () => "GORM Exec builds SQL via formatting or concatenation.",
    ).filter(() => /gorm\.io\/gorm|"github\.com\/jinzhu\/gorm"/.test(file.current)),
  ];

  // Deduplicate same line
  const seen = new Set<string>();
  return signals.filter((s) => {
    const key = `${s.ruleId}:${s.path}:${s.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * Only flag real database/sql (and known driver/ORM) Query/Exec calls.
 * net/http URL query strings use r.URL.Query() / Query().Get — never DB APIs.
 * Prefer silence when the call site is ambiguous.
 */
function contextlessQuerySignals(file: SourceRevision) {
  // Test files are almost always URL fixtures or mocks for this false-positive class.
  if (file.path.endsWith("_test.go")) return [];
  if (!hasDatabaseImport(file.current)) return [];

  return lineSignals(
    file,
    "go-database.contextless-query",
    /\.(?:Query|Exec)\s*\(/,
    () => "This database operation has no cancellation context.",
  ).filter((signal) => isLikelyDatabaseQueryOrExec(signal.snippet, file.current));
}

function hasDatabaseImport(source: string): boolean {
  return /"(?:database\/sql|github\.com\/(?:lib\/pq|jackc\/pgx(?:\/v\d+)?|jmoiron\/sqlx|go-sql-driver\/mysql|mattn\/go-sqlite3|uptrace\/bun|go-gorm\/gorm)|gorm\.io\/gorm|entgo\.io\/ent)/.test(
    source,
  );
}

export function isLikelyDatabaseQueryOrExec(line: string, fileSource = ""): boolean {
  const snippet = line.trim();
  // HTTP / net/url query-string APIs (zero-arg Query, chained Get/Encode, URL.Query).
  if (/\.URL\.Query\s*\(/.test(snippet)) return false;
  if (/\bQuery\s*\(\s*\)/.test(snippet)) return false;
  if (/\burl\.Values\b/.test(snippet)) return false;
  if (/\.Query\s*\(\s*\)\s*\.\s*(?:Get|Set|Add|Del|Encode|Has)\s*\(/.test(snippet)) return false;

  // database/sql Query/Exec take a query string (or ctx for *Context). Contextless
  // forms are Query(query, args...) / Exec(query, args...).
  const looksLikeSqlCall =
    /\.(?:Query|Exec)\s*\(\s*(?:`[^`]*`|"[^"]*"|'[A-Za-z]|\w+\s*,)/.test(snippet) ||
    /\b(?:db|tx|conn|stmt|sqlDB|pool|queries|rawDB)\s*\.\s*(?:Query|Exec)\s*\(/i.test(snippet);

  if (!looksLikeSqlCall) return false;

  // Extra guard: file without DB imports should never reach here, but keep silence.
  if (fileSource && !hasDatabaseImport(fileSource)) return false;

  return true;
}
