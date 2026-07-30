package main
import "database/sql"
func q(db *sql.DB, id string) { db.Query("select 1 from t where id=$1", id) }
