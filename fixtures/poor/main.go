package poor

import (
	"context"
	"database/sql"
)

func load(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, "select id from jobs")
	_ = rows
	return err
}
