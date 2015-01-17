package main

import (
	"errors"
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
	listenerChan <- ln

	localAddresses, err := getLocalAddresses()
	if err != nil {
		log.Println("Error getting list of this server's IP addresses:", err)
		// Continue, but without protection against infinite redirect loops.
	}

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

		serverAddr, err := realServerAddress(conn)
		if err != nil {
			log.Printf("Error getting original address for intercepted connection from %v: %v", conn.RemoteAddr(), err)
			continue
		}
		user, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

		var server string
		if tcpAddr, ok := serverAddr.(*net.TCPAddr); ok {
			server = tcpAddr.IP.String()
		} else {
			server = serverAddr.String()
		}
		if localAddresses[server] {
			// This is not an intercepted connection; it is a direct connection to
			// our transparent port. If we bump it, we will end up with an infinite
			// loop of redirects.
			logTLS(user, serverAddr.String(), "", errors.New("infinite redirect loop"))
			conn.Close()
			continue
		}

		go SSLBump(conn, serverAddr.String(), user, "")
	}

	panic("unreachable")
}

// getLocalAddresses returns a set of the IP addresses of this machine's
// network interfaces.
func getLocalAddresses() (map[string]bool, error) {
	res := map[string]bool{}

	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifs {
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, a := range addrs {
			if ipNet, ok := a.(*net.IPNet); ok {
				a = &net.IPAddr{IP: ipNet.IP}
			}
			res[a.String()] = true
		}
	}

	return res, nil
}
