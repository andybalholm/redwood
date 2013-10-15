package main

import (
	"log"
	"net"
	"net/url"
	"time"
)

// Transparently intercept HTTPS connections.

// runTransparentServer transparently intercepts connections, listening at addr.
func runTransparentServer(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	listenerChan <- ln

	var tempDelay time.Duration

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				log.Printf("Accept error: %v; retrying in %v", err, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			return err
		}

		serverAddr, err := realServerAddress(&conn)
		if err != nil {
			log.Println("Error getting original address for intercepted connection:", err)
			continue
		}
		if tlsReady {
			go SSLBump(conn, serverAddr, "")
		} else {
			go checkSSLHost(conn, serverAddr)
		}
	}

	panic("unreachable")
}

// checkSSLHost does hostname filtering on an SSL connection when full ssl
// filtering can't be done because no root certificate is installed.
func checkSSLHost(conn net.Conn, serverAddr string) {
	// Read the client hello so that we can find out the name of the server (not
	// just the address).
	clientHello, err := readClientHello(conn)
	if err != nil {
		log.Printf("error reading client hello in TLS connection from %s to %s: %s", conn.RemoteAddr(), serverAddr, err)
		connectDirect(conn, serverAddr, clientHello)
		return
	}

	serverName, ok := clientHelloServerName(clientHello)
	if ok && serverName != "" {
		if *tlsVerbose {
			log.Printf("Server name requested for %s is %s.", serverAddr, serverName)
		}
	} else {
		serverName = serverNameAtAddress(serverAddr)
		if *tlsVerbose {
			log.Printf("Server name detected at %s is %s.", serverAddr, serverName)
		}
	}

	sc := scorecard{
		tally: URLRules.MatchingRules(&url.URL{
			Scheme: "https",
			Host:   serverName,
		}),
	}
	sc.calculate("")
	if sc.action == BLOCK {
		log.Println("Blocked HTTPS connection to", serverName)
		conn.Close()
		return
	}

	connectDirect(conn, serverAddr, clientHello)
}
