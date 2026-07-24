package good

import (
	"context"
	"database/sql"
)

func update(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, "update jobs set ready = true")
	return err
}
