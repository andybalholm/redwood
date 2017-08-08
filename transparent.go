package main

import (
	"errors"
	"log"
	"net"
	"time"
)

// Transparently intercept HTTPS connections.

var localAddresses map[string]bool

func init() {
	var err error
	localAddresses, err = getLocalAddresses()
	if err != nil {
		log.Println("Error getting list of this server's IP addresses:", err)
	}
}

// runTransparentServer transparently intercepts connections, listening at addr.
func runTransparentServer(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	go func() {
		<-shutdownChan
		ln.Close()
	}()

	ln = tcpKeepAliveListener{ln.(*net.TCPListener)}

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

		go func() {
			user, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

			serverAddr, err := realServerAddress(conn)
			if err != nil {
				// We can't get the original address of the connnection; maybe it was intercepted
				// remotely or by an unsupported firewall. But we'll proceed and hope it has Server
				// Name Indication.
				SSLBump(conn, "", user, "", nil)
				return
			}

			if isLocalAddress(serverAddr) {
				// This is not an intercepted connection; it is a direct connection to
				// our transparent port. If we bump it, we will end up with an infinite
				// loop of redirects.
				logTLS(user, serverAddr.String(), "", errors.New("infinite redirect loop"), false)
				conn.Close()
				return
			}

			SSLBump(conn, serverAddr.String(), user, "", nil)
		}()
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

// isLocalAddress returns whether addr is an address on this machine.
func isLocalAddress(addr net.Addr) bool {
	var host string
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		host = tcpAddr.IP.String()
	} else {
		host = addr.String()
	}
	return localAddresses[host]
}
