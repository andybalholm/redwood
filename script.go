package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
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

func (c *config) loadResponseACLScript(filename string) error {
	p, err := loadScript(filename)
	if err != nil {
		return err
	}

	c.ACLs.ResponseScripts = append(c.ACLs.ResponseScripts, p)
	return nil
}

// jsRuntime returns a new JavaScript runtime, with some useful global
// variables and functions defined.
func jsRuntime() *goja.Runtime {
	rt := goja.New()
	rt.Set("lookupHost", lookupHost)
	rt.Set("httpClient", new(http.Client))
	rt.Set("copyBody", copyBody)
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

// copyBody returns a copy of the body of an http.Request or http.Response.
func copyBody(r interface{}) (io.ReadCloser, error) {
	var originalBody io.ReadCloser
	switch r := r.(type) {
	case *http.Request:
		originalBody = r.Body
	case *http.Response:
		originalBody = r.Body
	default:
		return nil, fmt.Errorf("unsupported type (%T) for copyBody", r)
	}

	content, err := ioutil.ReadAll(originalBody)
	if err != nil {
		return nil, err
	}

	newBody := ioutil.NopCloser(bytes.NewReader(content))
	switch r := r.(type) {
	case *http.Request:
		r.Body = newBody
	case *http.Response:
		r.Body = newBody
	}

	return ioutil.NopCloser(bytes.NewReader(content)), nil
}
