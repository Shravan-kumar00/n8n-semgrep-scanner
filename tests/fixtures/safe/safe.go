package main

import (
	"crypto/sha256"
	"database/sql"
	"os"
	"os/exec"
)

var password = os.Getenv("DB_PASSWORD")

func find(db *sql.DB, name string) {
	db.Query("SELECT * FROM users WHERE name = $1", name)
	exec.Command("tar", "czf", "/tmp/x.tgz", name).Run()
	exec.Command("sh", "-c", "uptime").Run()
	sha256.Sum256([]byte(name))
}
