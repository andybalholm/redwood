package main

import (
	"log"
	"net/http"
	"net/http/cgi"
	"os"
	"path/filepath"
)

// The built-in web server, which serves URLs under http://203.0.113.1/

const localServer = "203.0.113.1"

func (c *config) startWebServer() {
	if c.StaticFilesDir != "" {
		c.ServeMux.Handle("/", http.FileServer(http.Dir(c.StaticFilesDir)))
	}

	if c.CGIBin != "" {
		dir, err := os.Open(c.CGIBin)
		if err != nil {
			log.Println("Could not open CGI directory:", err)
			return
		}
		defer dir.Close()

		info, err := dir.Readdir(0)
		if err != nil {
			log.Println("Could not read CGI directory:", err)
			return
		}

		for _, fi := range info {
			if mode := fi.Mode(); (mode&os.ModeType == 0) && (mode.Perm()&0100 != 0) {
				// It's an executable file.
				name := "/" + fi.Name()
				scriptPath := filepath.Join(c.CGIBin, fi.Name())
				c.ServeMux.Handle(name, &cgi.Handler{
					Path: scriptPath,
				})
			}
		}
	}
}
