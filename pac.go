package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
)

var perUserPorts chan int

// handlePACFile serves an automatically-generated PAC (Proxy Auto-Config) file
// pointing to this proxy server.
func handlePACFile(w http.ResponseWriter, r *http.Request) {
	conf := getConfig()

	proxyAddr := conf.PACAddress

	client := r.RemoteAddr
	host, _, err := net.SplitHostPort(client)
	if err == nil {
		client = host
	}
	if lanAddress(client) && conf.PACLANAddress != "" {
		proxyAddr = conf.PACLANAddress
	}

	user, pass := r.FormValue("u"), r.FormValue("p")
	if perUserPorts != nil && user != "" && pass != "" && conf.ValidCredentials(user, pass) {
		// Open a separate, pre-authenticated listener for this user.
		port := getPersonalProxyPort(user, client)
		proxyHost, _, err := net.SplitHostPort(proxyAddr)
		if err != nil {
			log.Printf("invalid pac-address value (%q)", proxyAddr)
			http.Error(w, "can't generate PAC file", 500)
			return
		}
		proxyAddr = net.JoinHostPort(proxyHost, strconv.Itoa(port))
	}

	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	fmt.Fprintf(w, pacTemplate, proxyAddr)
}

var pacTemplate = `function FindProxyForURL(url, host) {
	if (
		shExpMatch(url, "ftp:*") ||
		host == "localhost" ||
		isInNet(host, "127.0.0.0", "255.0.0.0") ||
		isInNet(host, "10.0.0.0", "255.0.0.0") ||
		isInNet(host, "172.16.0.0", "255.240.0.0") ||
		isInNet(host, "192.168.0.0", "255.255.0.0")
	) {
		return "DIRECT";
	}

	return "PROXY %s";
}`

// getPersonalProxyPort returns a port number that user may
// connect to from clientIP. If none is available, it starts a new listener.
func getPersonalProxyPort(user string, clientIP string) int {
	proxyForUserLock.RLock()
	p := proxyForUser[user]
	proxyForUserLock.RUnlock()

	if p == nil {
		// Start a new proxy listener for this user.
		port := <-perUserPorts
		p = &perUserProxy{
			User:    user,
			Port:    port,
			Handler: proxyHandler{user: user},
		}
		proxyForUserLock.Lock()
		proxyForUser[user] = p
		proxyForUserLock.Unlock()
		listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			log.Printf("error opening per-user listener for %s on port %d: %v", user, port, err)
			return port
		}

		go func() {
			<-shutdownChan
			listener.Close()
		}()

		server := http.Server{Handler: p}
		go server.Serve(listener)
		log.Printf("opened per-user listener for %s on port %d", user, port)
	}

	p.AllowIP(clientIP)

	return p.Port
}

type perUserProxy struct {
	User          string
	Port          int
	Handler       http.Handler
	allowedIPs    map[string]bool
	allowedIPLock sync.RWMutex
}

func (p *perUserProxy) AllowIP(ip string) {
	p.allowedIPLock.Lock()
	if p.allowedIPs == nil {
		p.allowedIPs = make(map[string]bool)
	}
	p.allowedIPs[ip] = true
	p.allowedIPLock.Unlock()
}

func (p *perUserProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	p.allowedIPLock.RLock()
	ok := p.allowedIPs[host]
	p.allowedIPLock.RUnlock()
	if !ok {
		http.Error(w, "Unauthorized IP address", http.StatusForbidden)
		return
	}
	p.Handler.ServeHTTP(w, r)
}

var proxyForUser = make(map[string]*perUserProxy)
var proxyForUserLock sync.RWMutex
