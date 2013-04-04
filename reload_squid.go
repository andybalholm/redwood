package main

import (
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// squidPIDFiles contains places to look for Squid's PID file.
var squidPIDFiles = []string{
	"/var/run/squid.pid",
	"/var/run/squid/squid.pid",
}

// reloadSquid sends SIGHUP to Squid to make it reload its configuration.
func reloadSquid() {
	for _, pidFile := range squidPIDFiles {
		fi, err := os.Stat(pidFile)
		if err != nil {
			continue
		}
		mode := fi.Mode()
		if mode&os.ModeType != 0 {
			// It's not a regular file.
			continue
		}
		data, err := ioutil.ReadFile(pidFile)
		if err != nil {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil {
			continue
		}
		squid, err := os.FindProcess(pid)
		if err != nil {
			continue
		}
		defer squid.Release()
		squid.Signal(syscall.SIGHUP)
	}
}
