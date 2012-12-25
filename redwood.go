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
var pidfile = flag.String("pidfile", "/var/run/redwood.pid", "path of file to store process ID")
var listenAddress = flag.String("listen-address", ":8000", "address (host:port) to listen for proxy connections on")

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

	runtime.GOMAXPROCS(runtime.NumCPU())

	if *testURL != "" {
		runURLTest(*testURL)
		return
	}

	go accessLog()

	startWebServer()

	err := http.ListenAndServe(*listenAddress, proxyHandler{})
	if err != nil {
		log.Println("Error running proxy server:", err)
	}
}
