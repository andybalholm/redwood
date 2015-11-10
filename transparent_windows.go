package main

import (
	"errors"
	"net"
)

var errNoTransparentHTTPSOnWindows = errors.New("transparent HTTPS interception is not supported on Windows")

func realServerAddress(conn net.Conn) (net.Addr, error) {
	return nil, errNoTransparentHTTPSOnWindows
}
