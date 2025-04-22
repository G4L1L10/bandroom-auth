package db

import (
	"database/sql"
	"fmt"
	"log"

	"github.com/g4l1l10/bandroom/authentication/config"

	_ "github.com/lib/pq"
)

var DB *sql.DB

func ConnectDatabase() {
	var err error

	DB, err = sql.Open("postgres", config.Config.DatabaseURL)
	if err != nil {
		log.Fatalf("Error opening database: %v", err)
	}

	if err = DB.Ping(); err != nil {
		log.Fatalf("Cannot connect to database: %v", err)
	}

	fmt.Println("Connected to the database successfully!")
}

func CloseDatabase() {
	if DB != nil {
		DB.Close()
	}
}
