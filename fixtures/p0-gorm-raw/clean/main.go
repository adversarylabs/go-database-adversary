package main

import "gorm.io/gorm"

func findUser(db *gorm.DB, id string) {
	// Clean: bound parameter
	db.Raw("SELECT * FROM users WHERE id = ?", id).Scan(nil)
}

func deleteUser(db *gorm.DB, id string) {
	db.Exec("DELETE FROM users WHERE id = ?", id)
}
