package main

import (
	"errors"
	"net"
	"reflect"
	"strconv"
	"syscall"
	"unsafe"
)

type sockaddr struct {
	family uint16
	data   [14]byte
}

const SO_ORIGINAL_DST = 80

// realServerAddress returns an intercepted connection's original destination.
func realServerAddress(conn net.Conn) (string, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return "", errors.New("not a TCPConn")
	}

	TCPConn := reflect.ValueOf(tcpConn).Elem()
	netFD := TCPConn.FieldByName("fd").Elem()
	fd := netFD.FieldByName("sysfd").Int()

	var addr sockaddr
	size := uint32(unsafe.Sizeof(addr))
	err := getsockopt(int(fd), syscall.SOL_IP, SO_ORIGINAL_DST, unsafe.Pointer(&addr), &size)
	if err != nil {
		return "", err
	}

	var ip net.IP
	switch addr.family {
	case syscall.AF_INET:
		ip = addr.data[2:6]
	default:
		return "", errors.New("unrecognized address family")
	}

	port := int(addr.data[0])<<8 + int(addr.data[1])

	return net.JoinHostPort(ip.String(), strconv.Itoa(port)), nil
}
