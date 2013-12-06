package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
)

// HTTP proxy authentication.

var passwordFile = newActiveFlag("password-file", "", "path to file of usernames and passwords", readPasswordFile)
var authHelper = newActiveFlag("auth-helper", "", "program to authenticate users", startAuthHelper)
var authAlways = flag.Bool("always-require-auth", false, "require authentication even for LAN users")
var authNever = flag.Bool("disable-auth", false, "never require authentication")

var passwords = map[string]string{}
var passwordLock sync.RWMutex

var authenticators []func(user, password string) bool

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

	if password == "" {
		send407(w)
		return ""
	}

	passwordLock.RLock()
	ok := password == passwords[user]
	passwordLock.RUnlock()
	if ok {
		return user
	}

	for _, a := range authenticators {
		if a(user, password) {
			if _, ok := passwords[user]; !ok {
				// Cache the password for later use.
				passwordLock.Lock()
				passwords[user] = password
				passwordLock.Unlock()
			}
			return user
		}
	}

	send407(w)
	return ""
}

func startAuthHelper(cmd string) error {
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
	authenticators = append(authenticators, func(user, password string) bool {
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
