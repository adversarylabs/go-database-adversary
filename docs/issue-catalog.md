# go/database — issue catalog

This document is the **issue catalog** for this adversary: the classes of defects we aim to find, how we detect them (static vs LLM), public pattern references, and staff priority (P0 / P1 / LLM-only / Cut).

It is documentation and roadmap for contributors — not a runtime contract. Implemented detectors live in `src/` with fixtures under `fixtures/`; the **Review verdicts** section records what ships first.

Public examples cited below illustrate bad patterns only. Do not scrape secrets from them or copy copyrighted code into fixtures.

**Catalog id:** `go/database`  
**Status:** public OSS documentation of the issue classes this adversary targets  
**Goal:** trusted, high-precision detections. Prefer missing a weak signal over a false positive.

## Mission
Safe, reliable Go data access: injection immunity, transaction correctness, pool hygiene, and migration discipline.

## LLM strategy (required for world-class)
**Enhance:** transaction completeness stories; distinguish SQL builders that are safe.
**Discover:** N+1, isolation mistakes, soft-delete bypasses.

### Division of labor
| Layer | Responsibility |
| --- | --- |
| **Static / structural** | Deterministic signals with line-level evidence. |
| **LLM enhancement** | Impact, multi-file stories, FP suppression. |
| **LLM discovery** | Novel issues only with concrete evidence. |

### Trust / anti-FP rules
Evidence required; LLM-only defaults medium/low; when unsure omit.

## Review verdicts (staff pass)

- **P0 implement:** `sql.injection-fmt`, `gorm.raw`, `tx.missing-rollback`, `rows.not-closed`, `secrets.inline-dsn`, `dsn.password-log`
- **P1:** `sql.injection-builder`, `tx.missing-context`, `conn.max-lifetime`, `conn.max-open-zero`, `migrate.unsafe`, `nullable.unchecked`, `context.todo`, `tx.nested`, `batch.no-limit`, `error.leak`, `ping.missing`
- **LLM-only:** `n-plus-one`, `isolation.default`, `soft-delete.bypass`, `migration.lossy`, `read-replica.stale`, `tx.slow-work-inside`, `replication.ddl-session-state`
- **Cut:** `prepared.missing` — database/sql and pgx already cache prepared statements; pure noise. `pgx.simple-protocol` — pgx sanitizes parameters in simple-protocol mode; esoteric with no clear exploit story. `time.now-sql` — vague and unactionable as a finding.

## Issue catalog

---
### 1. `go-db.sql.injection-fmt` — fmt.Sprintf SQL

| Field | Value |
| --- | --- |
| **Severity** | critical |
| **Target confidence** | high |

**What it is.** SQL built with fmt.Sprintf/string concat.

**Static detection.** Detect Sprintf to Query/Exec strings.

**LLM role.** Confirm user input involvement via LLM.

**False-positive guards.** Ident allowlists for columns.

**Public examples of the bad pattern:**
  - https://go.dev/doc/database/sql-inject
  - https://github.com/securego/gosec — G201
  - https://github.com/OWASP/Go-SCP

---
### 2. `go-db.sql.injection-builder` — String builder query assembly

| Field | Value |
| --- | --- |
| **Severity** | critical |
| **Target confidence** | medium |

**What it is.** bytes.Buffer SQL assembly with user values.

**Static detection.** Heuristic + LLM.

**LLM role.** Same as above.

**False-positive guards.** Pure static fragments.

**Public examples of the bad pattern:**
  - https://go.dev/doc/database/sql-inject
  - https://github.com/securego/gosec
  - https://github.com/jackc/pgx

---
### 3. `go-db.tx.missing-context` — Begin without context

| Field | Value |
| --- | --- |
| **Severity** | low |
| **Target confidence** | high |

**What it is.** db.Begin() vs BeginTx(ctx).

**Static detection.** AST detect Begin().

**LLM role.** Recommend BeginTx; plain Begin() is legitimate in short-lived CLIs — keep severity low.

**False-positive guards.** Legacy code paths mid-migration.

**Public examples of the bad pattern:**
  - https://pkg.go.dev/database/sql#DB.BeginTx
  - https://go.dev/doc/database/manage-connections
  - https://github.com/jackc/pgx

---
### 4. `go-db.tx.missing-rollback` — Transaction without defer rollback

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | medium |

**What it is.** BeginTx without defer tx.Rollback pattern.

**Static detection.** Control-flow heuristic.

**LLM role.** LLM: is commit/rollback complete?

**False-positive guards.** Helper wrappers handling lifecycle.

**Public examples of the bad pattern:**
  - https://go.dev/doc/database/execute-transactions
  - https://github.com/jackc/pgx
  - https://pkg.go.dev/database/sql#Tx

---
### 5. `go-db.rows.not-closed` — Query rows without Close/err check

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |

**What it is.** rows, err := db.Query; missing defer rows.Close().

**Static detection.** AST resource check.

**LLM role.** Also require rows.Err().

**False-positive guards.** sqlx/struct scan helpers that close.

**Public examples of the bad pattern:**
  - https://go.dev/doc/database/querying
  - https://github.com/jmoiron/sqlx
  - https://pkg.go.dev/database/sql#Rows.Close

---
### 6. `go-db.conn.max-lifetime` — Pool without SetConnMaxLifetime

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | high |

**What it is.** sql.DB pool defaults may hold stale connections.

**Static detection.** Detect Open without pool tuning for long-lived services.

**LLM role.** Recommend MaxOpen/MaxIdle/Lifetime.

**False-positive guards.** Short-lived CLIs.

**Public examples of the bad pattern:**
  - https://go.dev/doc/database/manage-connections
  - https://pkg.go.dev/database/sql#DB.SetConnMaxLifetime
  - https://github.com/jackc/pgx

---
### 7. `go-db.conn.max-open-zero` — Unlimited MaxOpenConns

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | high |

**What it is.** SetMaxOpenConns(0) unlimited risks DB meltdown.

**Static detection.** Detect 0 or missing in high-QPS servers.

**LLM role.** Suggest bounds.

**False-positive guards.** Tiny tools.

**Public examples of the bad pattern:**
  - https://go.dev/doc/database/manage-connections
  - https://pkg.go.dev/database/sql#DB.SetMaxOpenConns
  - https://github.com/jackc/pgx/stdlib

---
### 8. `go-db.dsn.password-log` — Logging DSN/URL

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |

**What it is.** log.Print(dsn) includes password.

**Static detection.** Detect log of DSN variables.

**LLM role.** Redact.

**False-positive guards.** Printing driver name only.

**Public examples of the bad pattern:**
  - https://github.com/OWASP/Go-SCP
  - https://go.dev/blog/slog
  - https://github.com/securego/gosec

---
### 9. `go-db.migrate.unsafe` — Auto-migrate in production main

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | medium |

**What it is.** gorm AutoMigrate in server startup.

**Static detection.** Detect AutoMigrate in main/cmd.

**LLM role.** LLM: env gated?

**False-positive guards.** Dev commands.

**Public examples of the bad pattern:**
  - https://gorm.io/docs/migration.html
  - https://github.com/golang-migrate/migrate
  - https://github.com/pressly/goose

---
### 10. `go-db.n-plus-one` — Query inside loop over rows

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | low |

**What it is.** Classic N+1.

**Static detection.** Loop + Query pattern heuristic.

**LLM role.** LLM performance judgment.

**False-positive guards.** Batched intentional.

**Public examples of the bad pattern:**
  - https://gorm.io/docs/preload.html
  - https://github.com/jmoiron/sqlx
  - https://github.com/OWASP/Go-SCP

---
### 11. `go-db.nullable.unchecked` — Scan into non-null without Null* types

| Field | Value |
| --- | --- |
| **Severity** | low |
| **Target confidence** | medium |

**What it is.** Scan NULL into string causes errors/zeros.

**Static detection.** Hard statically; LLM + sql null types.

**LLM role.** Data correctness.

**False-positive guards.** NOT NULL columns proven.

**Public examples of the bad pattern:**
  - https://pkg.go.dev/database/sql#NullString
  - https://github.com/jackc/pgx
  - https://go.dev/doc/database/querying

---
### 12. `go-db.context.todo` — context.TODO in DB calls

| Field | Value |
| --- | --- |
| **Severity** | low |
| **Target confidence** | high |

**What it is.** QueryContext(context.TODO()).

**Static detection.** Detect TODO/Background in DB API.

**LLM role.** Request ctx preferred.

**False-positive guards.** Init migrations.

**Public examples of the bad pattern:**
  - https://go.dev/blog/context
  - https://pkg.go.dev/database/sql
  - https://github.com/jackc/pgx

---
### 13. `go-db.tx.nested` — Nested transactions fake

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | medium |

**What it is.** Begin while tx active without savepoints.

**Static detection.** Hard; LLM.

**LLM role.** Suggest savepoints.

**False-positive guards.** sqlx helpers.

**Public examples of the bad pattern:**
  - https://go.dev/doc/database/execute-transactions
  - https://github.com/jackc/pgx
  - https://www.postgresql.org/docs/current/sql-savepoint.html

---
### 14. `go-db.isolation.default` — Sensitive writes without isolation level

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | low |

**What it is.** Financial updates using default isolation.

**Static detection.** LLM domain discovery.

**LLM role.** Suggest Serializable/SSI discussion.

**False-positive guards.** Read-only.

**Public examples of the bad pattern:**
  - https://go.dev/doc/database/execute-transactions
  - https://www.postgresql.org/docs/current/transaction-iso.html
  - https://github.com/jackc/pgx

---
### 15. `go-db.gorm.raw` — gorm Exec raw with concatenation

| Field | Value |
| --- | --- |
| **Severity** | critical |
| **Target confidence** | high |

**What it is.** db.Exec("..."+user).

**Static detection.** Detect gorm raw APIs with concat.

**LLM role.** Same SQLi story.

**False-positive guards.** Parameterized raw.

**Public examples of the bad pattern:**
  - https://gorm.io/docs/sql_builder.html
  - https://github.com/securego/gosec
  - https://go.dev/doc/database/sql-inject

---
### 16. `go-db.soft-delete.bypass` — Hard delete helpers ignoring soft delete

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | low |

**What it is.** Unscoped deletes in GORM accidentally.

**Static detection.** Detect Unscoped().Delete.

**LLM role.** LLM intent.

**False-positive guards.** GDPR hard delete intentional.

**Public examples of the bad pattern:**
  - https://gorm.io/docs/delete.html
  - https://github.com/go-gorm/gorm
  - https://github.com/OWASP/Go-SCP

---
### 17. `go-db.migration.lossy` — Down migration drops data without guard

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | low |

**What it is.** DROP COLUMN in down without backup notes.

**Static detection.** SQL parse in migrate files.

**LLM role.** LLM review.

**False-positive guards.** Dev-only.

**Public examples of the bad pattern:**
  - https://github.com/golang-migrate/migrate
  - https://github.com/pressly/goose
  - https://github.com/golang-migrate/migrate/tree/master/database

---
### 18. `go-db.secrets.inline-dsn` — DSN constructed from hardcoded password

| Field | Value |
| --- | --- |
| **Severity** | critical |
| **Target confidence** | high |

**What it is.** password= literal in source.

**Static detection.** String literal detect.

**LLM role.** Secrets adversary overlap — still flag.

**False-positive guards.** Examples in docs.

**Public examples of the bad pattern:**
  - https://github.com/gitleaks/gitleaks
  - https://github.com/OWASP/wrongsecrets
  - https://go.dev/doc/database/sql-inject

---
### 19. `go-db.read-replica.stale` — Write-after-read on replica without sticky

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | low |

**What it is.** Architecture smell LLM discovery.

**Static detection.** Needs multi-file.

**LLM role.** Suggest primary sticky sessions.

**False-positive guards.** Eventual OK domains.

**Public examples of the bad pattern:**
  - https://github.com/go-sql-driver/mysql
  - https://www.postgresql.org/docs/current/hot-standby.html
  - https://github.com/jackc/pgx

---
### 20. `go-db.batch.no-limit` — IN clause built from unbounded user slice

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | medium |

**What it is.** Query IN (thousands of user ids).

**Static detection.** Detect join of user slice into SQL.

**LLM role.** DoS + injection.

**False-positive guards.** Bounded slices.

**Public examples of the bad pattern:**
  - https://go.dev/doc/database/sql-inject
  - https://github.com/jackc/pgx
  - https://github.com/jmoiron/sqlx

---
### 21. `go-db.error.leak` — Returning raw DB errors to clients

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | medium |

**What it is.** http.Error(w, err.Error()) from sql err.

**Static detection.** Detect err.Error write on sql errors.

**LLM role.** Wrap generic messages.

**False-positive guards.** Admin debug.

**Public examples of the bad pattern:**
  - https://github.com/OWASP/Go-SCP
  - https://go.dev/doc/database/querying
  - https://github.com/gin-gonic/gin

---
### 22. `go-db.ping.missing` — No health check of DB on startup

| Field | Value |
| --- | --- |
| **Severity** | low |
| **Target confidence** | medium |

**What it is.** Open without PingContext.

**Static detection.** Detect Open without Ping in main.

**LLM role.** Reliability.

**False-positive guards.** Lazy connect intentional.

**Public examples of the bad pattern:**
  - https://pkg.go.dev/database/sql#DB.PingContext
  - https://go.dev/doc/database/manage-connections
  - https://github.com/jackc/pgx

---
### 23. `go-db.tx.slow-work-inside` — Network calls or slow work inside an open transaction

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | low |

**What it is.** HTTP calls, queue publishes, or sleeps between Begin and Commit hold row locks and pool connections — a classic production-incident source (pool exhaustion, lock pileups).

**Static detection.** Weak signal only: http/queue client calls lexically between BeginTx and Commit. LLM-only discovery with evidence.

**LLM role.** Confirm the slow call is inside the transaction scope and not an intentional outbox/saga pattern.

**False-positive guards.** Outbox pattern; short idempotent calls with tight timeouts; advisory-lock flows.

**Public examples of the bad pattern:**
  - https://go.dev/doc/database/execute-transactions
  - https://www.postgresql.org/docs/current/explicit-locking.html
  - https://github.com/jackc/pgx

---
### 24. `go-db.replication.ddl-session-state` — Replicated DDL depends on primary-only session state

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | medium |

**What it is.** Go schema-management code establishes session or connection state before DDL, but replicas can evaluate the replicated statement under incompatible state.

**Static detection.** None; variable names and binlog metadata alone do not establish effective replica behavior.

**LLM role.** Connect the changed DDL path, session assignment, and concrete replica-applier evidence. Explain the resulting replication stop or schema divergence.

**False-positive guards.** Replica appliers explicitly establish compatible state; the DDL is local or not replicated; effective server behavior is absent from prepared evidence.

**Public example:**
  - https://github.com/vitessio/vitess/pull/20654

---

## Implementation roadmap (after approval)
1. P0 static rules + vulnerable/clean fixtures. 2. LLM enhancement. 3. Evidence-gated discovery. 4. Public-repo precision bake-off.

**P0 priorities:** SQL injection (fmt + gorm raw), missing Rollback, rows.Close, inline DSN passwords, DSN logging.
