package main

import (
	"log"
	"net"
	"time"
)

// Transparently intercept HTTPS connections.

// runTransparentServer transparently intercepts connections, listening at addr.
func runTransparentServer(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()

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

		serverAddr := realServerAddress(conn)
		go SSLBump(conn, serverAddr)
	}

	panic("unreachable")
}

// realServerAddress returns an intercepted connection's original destination.
// (This implementation is for FreeBSD.)
func realServerAddress(conn net.Conn) string {
	return conn.LocalAddr().String()
}
