// Redwood is an internet content-filtering program.
// It is designed to replace and improve on DansGuardian
// as the core of the Security Appliance internet filter.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strings"
)

var testURL = flag.String("test", "", "URL to test instead of running proxy server")
var pidfile = flag.String("pidfile", "", "path of file to store process ID")
var proxyAddresses = ListFlag("http-proxy", "address (host:port) to listen for proxy connections on")
var transparentAddresses = ListFlag("transparent-https", "address to listen for intercepted HTTPS connections on")

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

	if *testURL != "" {
		runURLTest(*testURL)
		return
	}

	go csvLog(*accessLogName, accessLogChan)
	go csvLog(*tlsLogName, tlsLogChan)

	startWebServer()

	portsListening := 0

	if len(*proxyAddresses) > 0 {
		for _, addr := range *proxyAddresses {
			proxyListener, err := net.Listen("tcp", addr)
			if err != nil {
				log.Fatalf("error listening for connections on %s: %s", addr, err)
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
	}

	if len(*transparentAddresses) > 0 {
		for _, addr := range *transparentAddresses {
			go func() {
				err := runTransparentServer(addr)
				if err != nil && !strings.Contains(err.Error(), "use of closed") {
					log.Fatalln("Error running transparent HTTPS proxy:", err)
				}
			}()
			portsListening++
		}
	}

	if portsListening > 0 {
		// Wait forever (or until somebody calls log.Fatal).
		select {}
	}
}
