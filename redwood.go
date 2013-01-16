// Redwood is an internet content-filtering program.
// It is designed to replace and improve on DansGuardian
// as the core of the Security Appliance internet filter.
package main

import (
	"code.google.com/p/go-icap"
	"flag"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
)

var testURL = flag.String("test", "", "URL to test instead of running ICAP server")
var pidfile = flag.String("pidfile", "", "path of file to store process ID")
var proxyAddress = flag.String("http-proxy", "", "address (host:port) to listen for proxy connections on")
var transparentAddress = flag.String("transparent-https", "", "address to listen for intercepted HTTPS connections on")
var icapAddress = flag.String("icap-server", "", "address to listen for ICAP connections on")

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

	portsListening := 0

	if *proxyAddress != "" {
		go func() {
			err := http.ListenAndServe(*proxyAddress, proxyHandler{})
			if err != nil {
				log.Fatalln("Error running HTTP proxy:", err)
			}
		}()
		portsListening++
	}

	if *transparentAddress != "" {
		if !tlsReady {
			log.Fatal("Can't run a transparent HTTPS proxy without server certificates configured.")
		}
		go func() {
			err := runTransparentServer(*transparentAddress)
			if err != nil {
				log.Fatalln("Error running transparent HTTPS proxy:", err)
			}
		}()
		portsListening++
	}

	if *icapAddress != "" {
		icap.HandleFunc("/reqmod", handleRequest)
		icap.HandleFunc("/respmod", handleResponse)
		go func() {
			err := icap.ListenAndServe(*icapAddress, nil)
			if err != nil {
				log.Fatalln("Error running ICAP server:", err)
			}
		}()
		portsListening++
	}

	if portsListening > 0 {
		// Wait forever (or until somebody calls log.Fatal).
		select {}
	}
}
