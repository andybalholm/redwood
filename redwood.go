// Redwood is an internet content-filtering program.
// It is designed to replace and improve on DansGuardian
// as the core of the Security Appliance internet filter.
package main

import (
	"code.google.com/p/go-icap"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"strings"
)

var testURL = flag.String("test", "", "URL to test instead of running ICAP server")
var pidfile = flag.String("pidfile", "", "path of file to store process ID")
var proxyAddress = flag.String("http-proxy", "", "address (host:port) to listen for proxy connections on")
var transparentAddress = flag.String("transparent-https", "", "address to listen for intercepted HTTPS connections on")
var icapAddress = flag.String("icap-server", "", "address to listen for ICAP connections on")

func main() {
	loadConfiguration()

	if *pidfile != "" {
		pid := os.Getpid()
		f, err := os.Create(*pidfile)
		if err == nil {
			fmt.Fprintln(f, pid)
			f.Close()
		} else {
			log.Println("could not create pidfile:", err)
		}
	}

	runtime.GOMAXPROCS(runtime.NumCPU())

	if *testURL != "" {
		runURLTest(*testURL)
		return
	}

	go accessLog()

	startWebServer()

	portsListening := 0

	if *proxyAddress != "" {
		proxyListener, err := net.Listen("tcp", *proxyAddress)
		if err != nil {
			log.Fatalf("error listening for connections on %s: %s", *proxyAddress, err)
		}
		listenerChan <- proxyListener
		server := http.Server{Handler: proxyHandler{}}
		go func() {
			err = server.Serve(proxyListener)
			if err != nil && !strings.Contains(err.Error(), "use of closed") {
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
			if err != nil && !strings.Contains(err.Error(), "use of closed") {
				log.Fatalln("Error running transparent HTTPS proxy:", err)
			}
		}()
		portsListening++
	}

	if *icapAddress != "" {
		icap.HandleFunc("/reqmod", handleRequest)
		icap.HandleFunc("/respmod", handleResponse)
		icapListener, err := net.Listen("tcp", *icapAddress)
		if err != nil {
			log.Fatalf("error listening for connections on %s: %s", *icapAddress, err)
		}
		listenerChan <- icapListener
		go func() {
			err := new(icap.Server).Serve(icapListener)
			if err != nil && !strings.Contains(err.Error(), "use of closed") {
				log.Fatalln("Error running ICAP server:", err)
			}
		}()
		portsListening++
		reloadSquid()
	}

	if portsListening > 0 {
		// Wait forever (or until somebody calls log.Fatal).
		select {}
	}
}
