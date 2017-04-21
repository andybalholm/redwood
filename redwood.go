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
	"time"
)

func main() {
	conf, err := loadConfiguration()
	if err != nil {
		log.Fatal(err)
	}
	configuration = conf

	accessLog.Open(conf.AccessLog)
	tlsLog.Open(conf.TLSLog)

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
		server := http.Server{
			Handler:     proxyHandler{},
			IdleTimeout: conf.CloseIdleConnections,
		}
		go func() {
			err := server.Serve(tcpKeepAliveListener{proxyListener.(*net.TCPListener)})
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

	conf.openPerUserPorts()
	portsListening += len(conf.CustomPorts)

	if portsListening > 0 {
		if conf.CloseIdleConnections > 0 {
			httpTransport.IdleConnTimeout = conf.CloseIdleConnections
			insecureHTTPTransport.IdleConnTimeout = conf.CloseIdleConnections
			go func() {
				for range time.Tick(conf.CloseIdleConnections) {
					http2Transport.CloseIdleConnections()
					insecureHTTP2Transport.CloseIdleConnections()
				}
			}()
		}

		// Wait forever (or until somebody calls log.Fatal).
		select {}
	}
}
