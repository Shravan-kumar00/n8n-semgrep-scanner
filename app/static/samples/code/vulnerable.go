// Sample - intentionally vulnerable Go service (for scanner demos)
package main

import (
	"crypto/md5"
	"crypto/tls"
	"database/sql"
	"fmt"
	"html/template"
	"net/http"
	"os/exec"
)

const slackToken = "xoxb-EXAMPLE-not-a-real-token"

var dbPassword = "Gopher!Secret99"

func handler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		rows, _ := db.Query(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name))
		defer rows.Close()
		out, _ := exec.Command("sh", "-c", "ping -c 1 "+r.URL.Query().Get("host")).Output()
		w.Write(out)
	}
}

func client() *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
}

func digest(b []byte) [16]byte { return md5.Sum(b) }

func greet(name string) template.HTML { return template.HTML("<b>" + name + "</b>") }

func main() {}
