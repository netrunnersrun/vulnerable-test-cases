package main

import (
	"database/sql"
	"fmt"
	"gorm.io/gorm"
)

// Matches: go-sqli-sprintf
func vulnerableSprintf(db *sql.DB, userInput string) (*sql.Rows, error) {
	query := fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", userInput)
	return db.Query(query)
}

// Matches: go-sqli-string-concat
func vulnerableConcat(db *sql.DB, userInput string) (*sql.Rows, error) {
	return db.Query("SELECT * FROM users WHERE name = '" + userInput + "'")
}

// Matches: go-sqli-exec-sprintf
func vulnerableExec(db *sql.DB, userInput string) (sql.Result, error) {
	return db.Exec(fmt.Sprintf("DELETE FROM users WHERE id = '%s'", userInput))
}

// Matches: go-gorm-raw-sprintf
func vulnerableGorm(db *gorm.DB, userInput string) *gorm.DB {
	return db.Raw(fmt.Sprintf("SELECT * FROM users WHERE email = '%s'", userInput))
}

// Safe: parameterized
func safeQuery(db *sql.DB, userInput string) (*sql.Rows, error) {
	return db.Query("SELECT * FROM users WHERE id = ?", userInput)
}
