// Redwood is an internet content-filtering program.
// It is designed to replace and improve on DansGuardian
// as the core of the Security Appliance internet filter.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
)

var testURL = flag.String("test", "", "URL to test instead of running ICAP server")
var cores = flag.Int("cores", runtime.NumCPU(), "number of CPU cores to use")
var pidfile = flag.String("pidfile", "/var/run/redwood.pid", "path of file to store process ID")

func main() {
	if *pidfile != "" {
		pid := os.Getpid()
		f, err := os.Create(*pidfile)
		if err == nil {
			fmt.Fprintln(f, pid)
			f.Close()
		}
	}

	loadConfiguration()

	runtime.GOMAXPROCS(*cores)

	if *testURL != "" {
		runURLTest(*testURL)
		return
	}

	go accessLog()

	startWebServer()

	err := http.ListenAndServe(":6502", proxyHandler{})
	if err != nil {
		log.Println("Error listening on port 6502:", err)
	}
}
