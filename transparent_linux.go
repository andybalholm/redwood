// +build linux,go1.9

package main

import (
	"errors"
	"net"
	"syscall"
	"unsafe"
)

type sockaddr struct {
	family uint16
	data   [14]byte
}

const SO_ORIGINAL_DST = 80

// realServerAddress returns an intercepted connection's original destination.
func realServerAddress(conn net.Conn) (net.Addr, error) {
	syscallConn, ok := conn.(syscall.Conn)
	if !ok {
		return nil, errors.New("can't get raw network connection")
	}
	rawConn, err := syscallConn.SyscallConn()
	if err != nil {
		return nil, err
	}

	var addr sockaddr
	var getsockoptErr error
	err = rawConn.Control(func(fd uintptr) {
		size := uint32(unsafe.Sizeof(addr))
		getsockoptErr = getsockopt(int(fd), syscall.SOL_IP, SO_ORIGINAL_DST, unsafe.Pointer(&addr), &size)
	})
	if err != nil {
		return nil, err
	}
	if getsockoptErr != nil {
		return nil, getsockoptErr
	}

	var ip net.IP
	switch addr.family {
	case syscall.AF_INET:
		ip = addr.data[2:6]
	default:
		return nil, errors.New("unrecognized address family")
	}

	port := int(addr.data[0])<<8 + int(addr.data[1])

	return &net.TCPAddr{IP: ip, Port: port}, nil
}
