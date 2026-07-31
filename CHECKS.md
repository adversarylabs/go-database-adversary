# Checks — what go/database detects

This file is the **public audit list** of detectors. If a rule id appears here, it is part of the product surface: it should fire on a vulnerable pattern, stay quiet on the documented clean case, and produce file:line evidence where applicable.

Runtime source of truth: [`src/domain.ts`](src/domain.ts).
Regression entry: graded fixtures and corpus under `test/`.

**Scope:** non-test `*.go` plus SQL migration files where applicable.

---

## Critical

### `go-database.rows-lifecycle`

| | |
| --- | --- |
| **What** | Query rows not closed by owner |
| **Why** | *sql.Rows holds a pool connection until Close |
| **Looks for** | `Query`/`QueryContext`/`Queryx` without `defer rows.Close()` |
| **Stays quiet when** | Immediate defer Close after successful Query |
| **Fixture** | `fixtures/` |
| **Remediation** | Always `defer rows.Close()` before scanning |

### `go-database.sql-injection`

| | |
| --- | --- |
| **What** | SQL built with string formatting |
| **Why** | User-controlled SQL fragments |
| **Looks for** | `Query`/`Exec` with `fmt.Sprintf` or string concat |
| **Stays quiet when** | Bound parameters only |
| **Remediation** | Use placeholders (`$1` / `?`) |

### `go-database.gorm-raw`

| | |
| --- | --- |
| **What** | GORM Raw/Exec via concatenation |
| **Why** | Raw SQL reintroduces injection |
| **Looks for** | GORM `Raw`/`Exec` with sprintf/concat |
| **Stays quiet when** | Bound parameters or expression builder |
| **Remediation** | `db.Raw("… ?", id)` |

### `go-database.inline-dsn-password`

| | |
| --- | --- |
| **What** | Hardcoded password in DSN |
| **Why** | Secrets in source/binary |
| **Looks for** | postgres/mysql/mongodb URL with embedded password |
| **Stays quiet when** | Password from env/secret manager |
| **Remediation** | Never commit DSN passwords |

## High

### `go-database.transaction-lifecycle`

| | |
| --- | --- |
| **What** | Transaction without rollback safety net |
| **Why** | Errors leave tx open and hold locks |
| **Looks for** | `Begin`/`BeginTx` without `defer tx.Rollback()` |
| **Stays quiet when** | Defer Rollback immediately after Begin |
| **Remediation** | Treat post-Commit rollback error as harmless |

### `go-database.dsn-logging`

| | |
| --- | --- |
| **What** | DSN or password logged |
| **Why** | Logs retain credentials |
| **Looks for** | log/slog/fmt of dsn/password/DATABASE_URL |
| **Stays quiet when** | No credential material in logs |
| **Remediation** | Redact connection strings |

## Medium

### `go-database.contextless-query`

| | |
| --- | --- |
| **What** | Database work ignores caller cancellation |
| **Why** | Timed-out work keeps consuming connections |
| **Looks for** | Query/Exec without Context variants |
| **Stays quiet when** | QueryContext/ExecContext with owning ctx |
| **Remediation** | Always pass request/worker context |
