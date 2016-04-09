package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
)

// handlePACFile serves an automatically-generated PAC (Proxy Auto-Config) file
// pointing to this proxy server.
func handlePACFile(w http.ResponseWriter, r *http.Request) {
	proxyAddr := r.Host

	if a := r.FormValue("a"); a != "" {
		if user, pass, ok := decodeBase64Credentials(a); ok {
			conf := getConfig()
			if conf.ValidCredentials(user, pass) {
				proxyForUserLock.RLock()
				p := proxyForUser[user]
				proxyForUserLock.RUnlock()
				if p != nil {
					client := r.RemoteAddr
					host, _, err := net.SplitHostPort(client)
					if err == nil {
						client = host
					}
					p.AllowIP(client)
					proxyHost, _, err := net.SplitHostPort(proxyAddr)
					if err == nil {
						proxyAddr = net.JoinHostPort(proxyHost, strconv.Itoa(p.Port))
					}
				}
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

type perUserProxy struct {
	User           string
	Port           int
	Handler        http.Handler
	ClientPlatform string
	allowedIPs     map[string]bool
	allowedIPLock  sync.RWMutex
}

func newPerUserProxy(user string, port int, clientPlatform string) (*perUserProxy, error) {
	p := &perUserProxy{
		User:           user,
		Port:           port,
		ClientPlatform: clientPlatform,
		Handler:        proxyHandler{user: user},
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

	pf := platform(r.Header.Get("User-Agent"))
	if p.ClientPlatform != "" && pf == p.ClientPlatform || darwinPlatforms[p.ClientPlatform] && pf == "Darwin" {
		log.Printf("Accepting %s as %s because of User-Agent string %q", host, p.ClientPlatform, r.Header.Get("User-Agent"))
		p.AllowIP(host)
		p.Handler.ServeHTTP(w, r)
		return
	}

	log.Printf("Missing required proxy authentication from %v to %v, on port %d", r.RemoteAddr, r.URL, p.Port)
	conf.send407(w)
}

var proxyForUser = make(map[string]*perUserProxy)
var proxyForUserLock sync.RWMutex

func openPerUserPorts(customPorts map[string]int, clientPlatforms map[string]string) {
	for user, port := range customPorts {
		proxyForUserLock.RLock()
		p := proxyForUser[user]
		proxyForUserLock.RUnlock()
		if p == nil {
			_, err := newPerUserProxy(user, port, clientPlatforms[user])
			if err != nil {
				log.Printf("error opening per-user listener for %s: %v", user, err)
			}
		}
	}
}

type portListEntry struct {
	User                 string
	Port                 int
	AuthenticatedClients []string
}

func handlePerUserPortList(w http.ResponseWriter, r *http.Request) {
	var data []portListEntry

	proxyForUserLock.RLock()

	for _, p := range proxyForUser {
		var clients []string
		p.allowedIPLock.RLock()

		for c := range p.allowedIPs {
			clients = append(clients, c)
		}

		p.allowedIPLock.RUnlock()

		data = append(data, portListEntry{
			User:                 p.User,
			Port:                 p.Port,
			AuthenticatedClients: clients,
		})
	}

	proxyForUserLock.RUnlock()

	ServeJSON(w, r, data)
}

func handlePerUserAuthenticate(w http.ResponseWriter, r *http.Request) {
	user := r.FormValue("user")
	if user == "" {
		http.Error(w, `You must specify which user to authenticate with the "user" form parameter.`, 400)
		return
	}
	proxyForUserLock.RLock()
	p := proxyForUser[user]
	proxyForUserLock.RUnlock()
	if p == nil {
		http.Error(w, user+" does not have a per-user proxy port set up.", 500)
		return
	}

	ip := r.FormValue("ip")
	if ip == "" {
		http.Error(w, `You must specify the client IP address with the "ip" form parameter.`, 400)
		return
	}

	p.AllowIP(ip)
	fmt.Fprintf(w, "Added %s as an authenticated IP address for %s.", ip, user)
}
