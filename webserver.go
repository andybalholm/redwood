package main

import (
	"flag"
	"log"
	"net/http"
	"net/http/cgi"
	"os"
	"path/filepath"
)

// The built-in web server, which serves URLs under http://203.0.113.1/

var staticFilesDir = flag.String("static-files-dir", "", "path to static files for built-in web server")
var cgiBin = flag.String("cgi-bin", "", "path to CGI files for built-in web server")

func startWebServer() {
	if *staticFilesDir != "" {
		http.Handle("/", http.FileServer(http.Dir(*staticFilesDir)))
	}

	if *cgiBin != "" {
		loadCGIHandlers()
	}
}

func loadCGIHandlers() {
	dir, err := os.Open(*cgiBin)
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
			scriptPath := filepath.Join(*cgiBin, fi.Name())
			http.Handle(name, &cgi.Handler{
				Path: scriptPath,
			})
		}
	}
}
