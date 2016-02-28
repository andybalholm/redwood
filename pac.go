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

	if a := r.FormValue("a"); a != "" {
		if user, pass, ok := decodeBase64Credentials(a); ok {
			if perUserPorts != nil && conf.ValidCredentials(user, pass) {
				// Open a separate, pre-authenticated listener for this user.
				port, err := getPersonalProxyPort(user, client)
				if err != nil {
					log.Printf("error opening per-user listener for %s: %v", user, err)
					http.Error(w, "Could not open per-user proxy port", 500)
					return
				}

				proxyHost, _, err := net.SplitHostPort(proxyAddr)
				if err != nil {
					log.Printf("invalid pac-address value (%q)", proxyAddr)
					http.Error(w, "can't generate PAC file", 500)
					return
				}
				proxyAddr = net.JoinHostPort(proxyHost, strconv.Itoa(port))
			}
		}
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
func getPersonalProxyPort(user string, clientIP string) (int, error) {
	proxyForUserLock.RLock()
	p := proxyForUser[user]
	proxyForUserLock.RUnlock()

	if p == nil {
		// Start a new proxy listener for this user.
		port := <-perUserPorts
		var err error
		p, err = newPerUserProxy(user, port)
		if err != nil {
			return 0, err
		}
	}

	p.AllowIP(clientIP)

	return p.Port, nil
}

type perUserProxy struct {
	User          string
	Port          int
	Handler       http.Handler
	allowedIPs    map[string]bool
	allowedIPLock sync.RWMutex
}

func newPerUserProxy(user string, port int) (*perUserProxy, error) {
	p := &perUserProxy{
		User:    user,
		Port:    port,
		Handler: proxyHandler{user: user},
	}
	proxyForUserLock.Lock()
	proxyForUser[user] = p
	proxyForUserLock.Unlock()
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}

	go func() {
		<-shutdownChan
		listener.Close()
	}()

	server := http.Server{Handler: p}
	go server.Serve(listener)
	log.Printf("opened per-user listener for %s on port %d", user, port)

	return p, nil
}

func (p *perUserProxy) AllowIP(ip string) {
	p.allowedIPLock.Lock()
	if p.allowedIPs == nil {
		p.allowedIPs = make(map[string]bool)
	}
	p.allowedIPs[ip] = true
	p.allowedIPLock.Unlock()
	log.Printf("Added IP address %s, authenticated as %s, on port %d", ip, p.User, p.Port)
}

func (p *perUserProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	p.allowedIPLock.RLock()
	ok := p.allowedIPs[host]
	p.allowedIPLock.RUnlock()

	if ok {
		p.Handler.ServeHTTP(w, r)
		return
	}

	// This client's IP address is not pre-authorized for this port, but
	// maybe it sent credentials and we can authorize it now.
	// We accept credentials in either the Proxy-Authorization header or
	// a URL parameter named "a".
	conf := getConfig()

	user, pass, ok := ProxyCredentials(r)
	if ok {
		if user == p.User && conf.ValidCredentials(user, pass) {
			p.AllowIP(host)
			p.Handler.ServeHTTP(w, r)
			return
		} else {
			log.Printf("Incorrect username or password in Proxy-Authorization header from %v: %s:%s, on port %d", r.RemoteAddr, user, pass, p.Port)
		}
	}

	user, pass, ok = decodeBase64Credentials(r.FormValue("a"))
	if ok {
		if user == p.User && conf.ValidCredentials(user, pass) {
			p.AllowIP(host)
			p.Handler.ServeHTTP(w, r)
			return
		} else {
			log.Printf("Incorrect username or password in URL parameter from %v: %s:%s, on port %d", r.RemoteAddr, user, pass, p.Port)
		}
	}

	log.Printf("Missing required proxy authentication from %v to %v, on port %d", r.RemoteAddr, r.URL, p.Port)
	conf.send407(w)
}

var proxyForUser = make(map[string]*perUserProxy)
var proxyForUserLock sync.RWMutex

func openPerUserPorts(customPorts map[string]int) {
	for user, port := range customPorts {
		proxyForUserLock.RLock()
		p := proxyForUser[user]
		proxyForUserLock.RUnlock()
		if p == nil {
			_, err := newPerUserProxy(user, port)
			if err != nil {
				log.Printf("error opening per-user listener for %s: %v", user, err)
			}
		}
	}
}
