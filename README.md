# Go Database adversary

Go Database reviews transactions, queries, pools, cancellation, and migrations across `database/sql`, pgx, sqlx, Bun, GORM, and sqlc.

The initial review focuses on rows and transaction lifecycle ownership plus context-aware database operations.

## Fixtures and calibration

Five graded fixtures own expected review snapshots. The 61-repository corpus calibrates transaction and resource-lifecycle judgment across libraries and services.

## Automatic detection

`adversary auto` selects Go Database for changed Go or SQL source. Runtime dependency and symbol context will later narrow this to database-relevant Go changes.

## Development

Run `npm test`, `adversary validate .`, and `adversary pack --check .`.
