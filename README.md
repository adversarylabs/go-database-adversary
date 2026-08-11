# go/database

**go/database** reviews Go database code for **transaction, row, pool, query, cancellation, migration, and replication** safety across `database/sql`, pgx, sqlx, Bun, GORM, and sqlc.

It is a **database domain reviewer**, not a schema linter. It prefers silence over style. When it reports, connection pools, transactions, or SQL boundaries are at risk.

## What it does

1. **Discovers** Go and SQL migration files relevant to DB access.
2. **Runs deterministic detectors** for lifecycle ownership and SQL injection shapes.
3. **Synthesizes a review** with severity, impact, and remediation.
4. Optionally **enhances** with a model when provided.

It never executes the scanned project as the product under review, never installs dependencies into it, and never needs network access to the target repository.

## What it detects

Every **shipped rule id**, severity, and short description lives in **[CHECKS.md](CHECKS.md)** — the audit surface for “what does this adversary look for?”

Highlights:

| Area | Examples |
| --- | --- |
| Rows lifecycle | `Query`/`QueryContext` without `defer rows.Close()` |
| Transactions | `Begin` without deferred `Rollback` |
| Cancellation | Contextless Query/Exec APIs |
| Injection | SQL string concat / `fmt.Sprintf`; GORM `Raw`/`Exec` concat |
| Secrets | DSN passwords inline; DSN/password logging |
| Model-assisted migration review | Session state that changes how replicated DDL is evaluated |

### Ownership boundaries

Other official adversaries own adjacent classes so findings stay non-duplicative:

| Concern | Owned by |
| --- | --- |
| Generic SQL injection and TLS/crypto in non-DB code | [`go/security`](https://github.com/adversarylabs/go-security-adversary) |
| HTTP body limits and client timeouts | [`go/http`](https://github.com/adversarylabs/go-http-adversary) |
| Committed cloud keys and PATs | [`security/secrets`](https://github.com/adversarylabs/secrets-adversary) |

## Precision stance

- **High confidence** only for deterministic, evidence-backed patterns.
- Clean fixtures must stay quiet; vulnerable fixtures must fire where graded fixtures exist.
- Prefer missing a weak signal over a false positive on normal production code.
