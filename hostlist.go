package main

import (
	"io"
	"net"
	"os"
	"strings"
)

// A HostList is a list of hostnames and IP addresses to match against.
type HostList struct {
	// hosts is a list of hostnames to match exactly.
	hosts map[string]bool

	// domains is a list of domains where subdomains should be matched too.
	domains []string

	// ranges is a list of IP address ranges.
	ranges []*net.IPNet
}

func NewHostList() *HostList {
	return &HostList{
		hosts: make(map[string]bool),
	}
}

// Load adds entries to hl from the file at filename.
func (hl *HostList) Load(filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	cr := newConfigReader(f)

	for {
		line, err := cr.ReadLine()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		if strings.HasPrefix(line, ".") {
			// This is a domain that we should match subdomains of too.
			hl.domains = append(hl.domains, line)
			hl.hosts[line[1:]] = true
			continue
		}

		if _, subnet, err := net.ParseCIDR(line); err == nil {
			// It's a network range, like 192.168.0.1/24.
			hl.ranges = append(hl.ranges, subnet)
			continue
		}

		hl.hosts[line] = true
	}
}

// Contains returns whether host matches the list.
func (hl *HostList) Contains(host string) bool {
	if hl.hosts[host] {
		return true
	}
	for _, d := range hl.domains {
		if strings.HasSuffix(host, d) {
			return true
		}
	}
	addr := net.ParseIP(host)
	if addr == nil {
		return false
	}
	for _, subnet := range hl.ranges {
		if subnet.Contains(addr) {
			return true
		}
	}
	return false
}
