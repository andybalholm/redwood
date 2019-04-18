package main

import (
	"errors"
	"io/ioutil"
	"net"
	"net/http"

	"github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/console"
	"github.com/dop251/goja_nodejs/require"
	"github.com/miekg/dns"
)

// loadScript loads and compiles a JavaScript file.
func loadScript(filename string) (*goja.Program, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	return goja.Compile(filename, string(b), true)
}

func (c *config) loadRequestACLScript(filename string) error {
	p, err := loadScript(filename)
	if err != nil {
		return err
	}

	c.ACLs.RequestScripts = append(c.ACLs.RequestScripts, p)
	return nil
}

// jsRuntime returns a new JavaScript runtime, with some useful global
// variables and functions defined.
func jsRuntime() *goja.Runtime {
	rt := goja.New()
	rt.Set("lookupHost", lookupHost)
	rt.Set("httpClient", new(http.Client))
	new(require.Registry).Enable(rt)
	console.Enable(rt)
	return rt
}

func lookupHost(args ...string) (string, error) {
	if len(args) == 0 {
		return "", errors.New("lookupHost needs 1 or 2 parameters: the hostname, and optionally the DNS server")
	}

	host := args[0]

	if len(args) == 1 {
		addrs, err := net.LookupHost(host)
		if err != nil {
			return "", err
		}
		if len(addrs) == 0 {
			return "", nil
		}
		return addrs[0], nil
	}

	host = dns.Fqdn(host)
	server := args[1]

	m := new(dns.Msg)
	m.SetQuestion(host, dns.TypeA)
	resp, err := dns.Exchange(m, net.JoinHostPort(server, "53"))
	if err != nil {
		return "", err
	}

	for _, a := range resp.Answer {
		if a, ok := a.(*dns.A); ok {
			return a.A.String(), nil
		}
	}

	return "", nil
}
