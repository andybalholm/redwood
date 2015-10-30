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
		go func() {
			<-shutdownChan
			proxyListener.Close()
		}()
		server := http.Server{Handler: proxyHandler{}}
		go func() {
			err := server.Serve(proxyListener)
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

	for _, addr := range conf.ClassifierAddresses {
		classifierListener, err := net.Listen("tcp", addr)
		if err != nil {
			log.Fatalf("error listening for classification requests on %s: %v", addr, err)
		}
		go func() {
			<-shutdownChan
			classifierListener.Close()
		}()
		server := http.Server{Handler: http.HandlerFunc(handleClassification)}
		go func() {
			err := server.Serve(classifierListener)
			if err != nil && !strings.Contains(err.Error(), "use of closed") {
				log.Fatalln("Error running classifier:", err)
			}
		}()
		portsListening++
	}

	if conf.PerUserPorts != "" {
		var start, end int
		_, err := fmt.Sscanf(conf.PerUserPorts, "%d-%d", &start, &end)
		if err != nil || end < start {
			log.Printf("invalid per-user-ports setting (%q)", conf.PerUserPorts)
		} else {
			perUserPorts = make(chan int)
			go func() {
				for i := start; i <= end; i++ {
					perUserPorts <- i
				}
			}()
		}
	}

	if portsListening > 0 {
		// Wait forever (or until somebody calls log.Fatal).
		select {}
	}
}
