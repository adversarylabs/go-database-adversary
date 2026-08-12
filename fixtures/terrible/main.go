package terrible

import (
	"context"
	"database/sql"
)

func transfer(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	rows, err := db.QueryContext(ctx, "select id from jobs")
	for rows.Next() {
	}
	_, _ = tx.Exec("update accounts set balance = 0")
	return err
}
