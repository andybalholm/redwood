// Redwood is an internet content-filtering program.
// It is designed to replace and improve on DansGuardian
// as the core of the Security Appliance internet filter.
package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strings"
)

func main() {
	go manageConfig()

	conf := getConfig()

	if conf.PIDFile != "" {
		pid := os.Getpid()
		f, err := os.Create(conf.PIDFile)
		if err == nil {
			fmt.Fprintln(f, pid)
			f.Close()
		} else {
			log.Println("could not create pidfile:", err)
		}
	}

	if conf.TestURL != "" {
		runURLTest(conf.TestURL)
		return
	}

	portsListening := 0

	for _, addr := range conf.ProxyAddresses {
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

	for _, addr := range conf.TransparentAddresses {
		go func() {
			err := runTransparentServer(addr)
			if err != nil && !strings.Contains(err.Error(), "use of closed") {
				log.Fatalln("Error running transparent HTTPS proxy:", err)
			}
		}()
		portsListening++
	}

	if portsListening > 0 {
		// Wait forever (or until somebody calls log.Fatal).
		select {}
	}
}
