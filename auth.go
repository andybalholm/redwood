package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

// HTTP proxy authentication.

var passwordFile = newActiveFlag("password-file", "", "path to file of usernames and passwords", readPasswordFile)
var passwords = map[string]string{}

func readPasswordFile(filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("could not open %s: %s", filename, err)
	}
	defer f.Close()
	cr := newConfigReader(f)

	for {
		line, err := cr.ReadLine()
		if err != nil {
			break
		}

		space := strings.IndexAny(line, " \t")
		if space == -1 {
			log.Println("malformed line in password file:", line)
			continue
		}

		user := line[:space]
		pass := strings.TrimSpace(line[space:])
		passwords[user] = pass
	}

	return nil
}

func send407(w http.ResponseWriter) {
	w.Header().Set("Proxy-Authenticate", "Basic realm=Redwood")
	http.Error(w, "Proxy authentication required", http.StatusProxyAuthRequired)
}

// authenticate checks if the client has a valid username and password.
// If so, it returns the username. If not, it generates an HTTP 407 response
// and returns the empty string.
func authenticate(w http.ResponseWriter, r *http.Request) string {
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" || !strings.HasPrefix(auth, "Basic ") {
		send407(w)
		return ""
	}

	auth = auth[len("Basic "):]
	auth = strings.TrimSpace(auth)
	enc := base64.StdEncoding
	buf := make([]byte, enc.DecodedLen(len(auth)))
	n, err := enc.Decode(buf, []byte(auth))
	if err != nil {
		send407(w)
		return ""
	}
	auth = string(buf[:n])

	colon := strings.Index(auth, ":")
	if colon == -1 {
		send407(w)
		return ""
	}

	user := auth[:colon]
	password := auth[colon+1:]

	if password != passwords[user] {
		send407(w)
		return ""
	}

	return user
}
