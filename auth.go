package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
)

// HTTP proxy authentication.

func (c *config) readPasswordFile(filename string) error {
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
		c.Passwords[user] = pass
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

	conf := getConfig()

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

	if password == "" {
		send407(w)
		return ""
	}

	conf.PasswordLock.RLock()
	ok := password == conf.Passwords[user]
	conf.PasswordLock.RUnlock()
	if ok {
		return user
	}

	for _, a := range conf.Authenticators {
		if a(user, password) {
			if _, ok := conf.Passwords[user]; !ok {
				// Cache the password for later use.
				conf.PasswordLock.Lock()
				conf.Passwords[user] = password
				conf.PasswordLock.Unlock()
			}
			return user
		}
	}

	send407(w)
	return ""
}

func (cf *config) startAuthHelper(cmd string) error {
	c := exec.Command(cmd)
	in, err := c.StdinPipe()
	if err != nil {
		return err
	}
	out, err := c.StdoutPipe()
	if err != nil {
		return err
	}
	err = c.Start()
	if err != nil {
		return err
	}

	var m sync.Mutex
	cf.Authenticators = append(cf.Authenticators, func(user, password string) bool {
		m.Lock()
		defer m.Unlock()
		fmt.Fprintln(in, user, password)
		var response string
		fmt.Fscanln(out, &response)
		if response == "OK" {
			return true
		}
		return false
	})

	return nil
}
