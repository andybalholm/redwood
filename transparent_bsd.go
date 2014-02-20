// +build darwin freebsd

package main

import (
	"net"
)

// realServerAddress returns an intercepted connection's original destination.
func realServerAddress(conn net.Conn) (string, error) {
	return conn.LocalAddr().String(), nil
}
