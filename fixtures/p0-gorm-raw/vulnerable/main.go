package main

import (
	"fmt"

	"gorm.io/gorm"
)

func findUser(db *gorm.DB, id string) {
	// Vulnerable: GORM Raw with string concatenation
	db.Raw("SELECT * FROM users WHERE id = " + id).Scan(nil)
}

func findByName(db *gorm.DB, name string) {
	// Vulnerable: GORM Raw with fmt.Sprintf
	db.Raw(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)).Scan(nil)
}

func deleteUser(db *gorm.DB, id string) {
	// Vulnerable: GORM Exec with concatenation
	db.Exec("DELETE FROM users WHERE id = " + id)
}
