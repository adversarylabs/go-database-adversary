package excellent

import (
	"context"
	"database/sql"
)

func load(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, "select id from jobs")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
	}
	if err := rows.Err(); err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	return tx.Commit()
}
