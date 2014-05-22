// +build darwin freebsd

package main

import (
	"net"
)

// realServerAddress returns an intercepted connection's original destination.
func realServerAddress(conn net.Conn) (net.Addr, error) {
	return conn.LocalAddr(), nil
}
