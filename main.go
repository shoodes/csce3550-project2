package main

import (
	"database/sql"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
)

func initDB(dbPath string) *sql.DB {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatalf("Error opening database: %v", err)
	}

	createTableSQL := `
	CREATE TABLE IF NOT EXISTS keys (
		kid INTEGER PRIMARY KEY AUTOINCREMENT,
		key BLOB NOT NULL,
		exp INTEGER NOT NULL
	);`

	if _, err = db.Exec(createTableSQL); err != nil {
		log.Fatalf("Error creating keys table: %v", err)
	}

	return db
}

func main() {
	db := initDB("totally_not_my_privateKeys.db")
	InitializeKeyStore(db)

	r := mux.NewRouter()
	r.HandleFunc("/.well-known/jwks.json", JWKSHandler(db)).Methods("GET")
	r.HandleFunc("/auth", AuthHandler(db)).Methods("POST")

	log.Println("Starting server on :8080")
	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
