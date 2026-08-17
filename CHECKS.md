# Checks

| Rule | Severity | Scans for |
| --- | --- | --- |
| `go-database.contextless-query` | Medium | Database work ignores caller cancellation |
| `go-database.dsn-logging` | High | DSN or password logged |
| `go-database.gorm-raw` | Critical | GORM Raw/Exec via concatenation |
| `go-database.inline-dsn-password` | Critical | Hardcoded password in DSN |
| `go-database.rows-iteration-error` | High | Row iteration errors silently truncate query results |
| `go-database.rows-lifecycle` | Critical | Query rows not closed by owner |
| `go-database.sql-injection` | Critical | SQL built with string formatting |
| `go-database.transaction-lifecycle` | High | Transaction without rollback safety net |
