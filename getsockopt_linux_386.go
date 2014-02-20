package main

import (
	"syscall"
	"unsafe"
)

const _GETSOCKOPT = 15

func getsockopt(s int, level int, name int, val unsafe.Pointer, vallen *uint32) (err error) {
	args := [5]uintptr{uintptr(s), uintptr(level), uintptr(name), uintptr(val), uintptr(unsafe.Pointer(vallen))}
	_, _, e1 := syscall.Syscall(syscall.SYS_SOCKETCALL, _GETSOCKOPT, uintptr(unsafe.Pointer(&args)), 0)
	if e1 != 0 {
		err = e1
	}
	return
}
