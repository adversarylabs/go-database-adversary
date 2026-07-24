package average

import "database/sql"

func load(db *sql.DB) error {
	rows, err := db.Query("select id from jobs")
	if rows != nil {
		defer rows.Close()
	}
	return err
}
