// +build darwin freebsd

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os/exec"
)

// realServerAddress returns an intercepted connection's original destination.
func realServerAddress(conn net.Conn) (net.Addr, error) {
	// If the connection was intercepted with an IPFW fwd rule,
	// its LocalAddr will be the original destination.
	addr := conn.LocalAddr()
	if !isLocalAddress(addr) {
		return addr, nil
	}

	// If the connection was intercepted with a PF rdr rule,
	// we need to examine the state table to find the original address.
	pfctl := exec.Command("pfctl", "-ss")
	stdout, err := pfctl.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("error getting output of pfctl -ss: %v", err)
	}
	if err := pfctl.Start(); err != nil {
		return nil, fmt.Errorf("error running pfctl -ss: %v", err)
	}

	defer pfctl.Wait()

	// Search for redirected connections matching the remote host and port.
	// The lines look like this:
	// all tcp 10.1.10.1:6502 (199.27.79.143:80) <- 10.1.10.203:62586       ESTABLISHED:ESTABLISHED
	//         dest. of rdr    real server addr     remote address
	remote := append([]byte(") <- "), conn.RemoteAddr().String()...)
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Bytes()
		if !bytes.HasPrefix(line, []byte("all tcp ")) {
			continue
		}
		loc := bytes.Index(line, remote)
		if loc == -1 {
			continue
		}
		openParen := bytes.LastIndex(line[:loc], []byte{'('})
		if openParen == -1 {
			continue
		}
		as := string(line[openParen+1 : loc])
		a, err := net.ResolveTCPAddr("tcp", as)
		if err != nil {
			return nil, fmt.Errorf("error parsing address %q: %v", as, err)
		}
		return a, nil
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading output of pfctl -ss: %v", err)
	}

	return addr, nil
}
