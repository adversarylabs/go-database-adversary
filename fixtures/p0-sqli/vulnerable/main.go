package main
import ("database/sql"; "fmt")
func q(db *sql.DB, id string) { db.Query(fmt.Sprintf("select 1 from t where id=%s", id)) }
