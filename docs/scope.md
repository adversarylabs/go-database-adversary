# go/database — mission and scope

Source of truth for what this adversary is *for*.

- **Package:** `go-database`
- **Factory routing:** human PR comments are attributed to this adversary only when they match **In scope**.
- **Languages / surfaces:** Go database

## Mission

Review Go database code for transactions, pools, queries, cancellation, migrations, and replication-sensitive DDL behavior.

## In scope (fair miss if humans raised it and we did not)

- Transaction boundaries; missing rollback
- Pool misconfiguration; connection leaks
- Query cancellation; context not passed to DB
- Unsafe string-built SQL in Go DB code
- Migration safety issues
- Session or connection state that can make replicated DDL evaluate differently on replicas

## Out of scope (not a miss for this adversary)

- Non-DB concurrency
- Generic distributed-systems compatibility without a database or DDL consequence
- Secrets scanning
- Non-Go

## Factory grading rule

- **In scope + human raised it + this adversary did not surface it** → real miss → suggested issue for **this** package
- **Out of scope** → do not grade as a miss for this adversary
- **Better fit for another adversary** → route there; do not double-count as a miss here
- **Unclear** → prefer out-of-scope for grading
