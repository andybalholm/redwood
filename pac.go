package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"go.starlark.net/starlark"
	"golang.org/x/net/publicsuffix"
)

// handlePACFile serves an automatically-generated PAC (Proxy Auto-Config) file
// pointing to this proxy server.
func handlePACFile(w http.ResponseWriter, r *http.Request) {
	proxyAddr := r.Header.Get("X-Forwarded-Host")
	if len(proxyAddr) == 0 {
		proxyAddr = r.Host
	}
	conf := getConfig()

	if a := r.FormValue("a"); a != "" {
		if user, pass, ok := decodeBase64Credentials(a); ok {
			if conf.ValidCredentials(user, pass) {
				port := conf.CustomPorts[user].Port
				customPortLock.RLock()
				p := customPorts[port]
				customPortLock.RUnlock()
				if p != nil {
					remoteAddr := clientIP((r))
					p.AllowIP(remoteAddr)
					logAuthEvent("pac-url-param", "correct", remoteAddr, p.Port, user, "", "", "", r, "Authenticated via query param in PAC URL")
					proxyHost, _, err := net.SplitHostPort(proxyAddr)
					if err == nil {
						proxyAddr = net.JoinHostPort(proxyHost, strconv.Itoa(p.Port))
					}
				}
			}
		}
	}

	pacTemplate := conf.PACTemplate
	if pacTemplate == "" {
		pacTemplate = standardPACTemplate
	}

	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	w.Header().Set("Content-Disposition", "attachment; filename=proxy.pac")
	if strings.Contains(pacTemplate, "%s") {
		fmt.Fprintf(w, pacTemplate, proxyAddr)
	} else {
		fmt.Fprint(w, pacTemplate)
	}
}

// clientIP returns the client's IP address—either the first public IP address
// from the X-Forwarded-For headers, or the address from r.RemoteAddr.
func clientIP(r *http.Request) string {
	for _, xff := range r.Header.Values("X-Forwarded-For") {
		for _, addr := range strings.Split(xff, ",") {
			addr = strings.TrimSpace(addr)
			a, err := netip.ParseAddr(addr)
			if err == nil && !a.IsLoopback() && !a.IsPrivate() {
				return addr
			}
		}
	}

	client := r.RemoteAddr
	host, _, err := net.SplitHostPort(client)
	if err == nil {
		return host
	}
	return client
}

const standardPACTemplate = `function FindProxyForURL(url, host) {
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

func (c *config) loadPACTemplate(filename string) error {
	t, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	c.PACTemplate = string(t)
	return nil
}

type perUserProxy struct {
	Port int

	expectedDomains  map[string]bool
	expectedIPBlocks []*net.IPNet
	ClientPlatform   string
	expectedNetLock  sync.RWMutex
}

func (p *perUserProxy) addExpectedNetwork(network string) {
	p.expectedNetLock.Lock()
	defer p.expectedNetLock.Unlock()
	if _, nw, err := net.ParseCIDR(network); err == nil {
		p.expectedIPBlocks = append(p.expectedIPBlocks, nw)
	} else if ip := net.ParseIP(network); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			p.expectedIPBlocks = append(p.expectedIPBlocks, &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)})
		} else {
			p.expectedIPBlocks = append(p.expectedIPBlocks, &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)})
		}
	} else {
		domain, err := publicsuffix.EffectiveTLDPlusOne(network)
		if err != nil {
			domain = network
		}
		p.expectedDomains[domain] = true
	}
}

func (c *config) newPerUserProxy(user string, portInfo customPortInfo) (*perUserProxy, error) {
	p := &perUserProxy{
		Port:            portInfo.Port,
		ClientPlatform:  portInfo.ClientPlatform,
		expectedDomains: map[string]bool{},
	}

	for _, network := range portInfo.ExpectedNetworks {
		p.addExpectedNetwork(network)
	}

	customPortLock.Lock()
	customPorts[portInfo.Port] = p
	customPortLock.Unlock()
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", portInfo.Port))
	if err != nil {
		return nil, err
	}
	listener = tcpKeepAliveListener{listener.(*net.TCPListener)}

	go func() {
		<-shutdownChan
		listener.Close()
	}()

	server := http.Server{
		Handler:     p,
		IdleTimeout: c.CloseIdleConnections,
	}
	go server.Serve(listener)
	log.Printf("opened per-user listener for %s on port %d", user, portInfo.Port)

	return p, nil
}

func (p *perUserProxy) AllowIP(ip string) {
	user, ok := getConfig().UserForPort[p.Port]
	if !ok {
		return
	}

	authCacheLock.Lock()
	usersForPort := authCache[p.Port]
	if usersForPort == nil {
		usersForPort = make(map[string]string)
		authCache[p.Port] = usersForPort
	}
	usersForPort[ip] = user
	authCacheLock.Unlock()
	log.Printf("Added IP address %s, authenticated as %s, on port %d", ip, user, p.Port)

	domain := rdnsDomain(ip)
	if domain != "" {
		p.expectedNetLock.Lock()
		alreadyExpected := p.expectedDomains[domain]
		if !alreadyExpected {
			p.expectedDomains[domain] = true
		}
		p.expectedNetLock.Unlock()
		if !alreadyExpected {
			log.Printf("Added %s to the list of expected domains on port %d", domain, p.Port)
		}
	}
}

// rdnsDomain returns the base domain name of ip's reverse-DNS hostname (or the
// empty string if it is unavailable).
func rdnsDomain(ip string) string {
	var host string
	names, err := net.LookupAddr(ip)
	if err == nil && len(names) > 0 {
		host = names[0]
	}
	if host == "" {
		return ""
	}
	host = strings.TrimSuffix(host, ".")
	domain, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return host
	}
	return domain
}

func (p *perUserProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	activeConnections.Add(1)
	defer activeConnections.Done()

	configuredUser := getConfig().UserForPort[p.Port]
	handler := proxyHandler{
		localPort: p.Port,
	}

	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	authCacheLock.RLock()
	cachedUser := authCache[p.Port][host]
	authCacheLock.RUnlock()

	if cachedUser == configuredUser {
		handler.ServeHTTPAuthenticated(w, r, host, configuredUser)
		return
	}

	// This client's IP address is not pre-authorized for this port, but
	// maybe it sent credentials and we can authorize it now.

	ui := &UserInfo{
		Request: r,
	}
	ui.Authenticate(p)

	if ui.AuthenticatedUser != "" && ui.AuthenticatedUser != configuredUser {
		logAuthEvent("custom-port", "invalid", r.RemoteAddr, p.Port, ui.AuthenticatedUser, "", p.ClientPlatform, "", r, fmt.Sprint("Expected username ", configuredUser))
		handler.ServeHTTPAuthenticated(w, r, host, "")
		return
	}

	if ui.AuthenticatedUser != "" {
		p.AllowIP(host)
		logAuthEvent("proxy-auth-header", "correct", r.RemoteAddr, p.Port, ui.AuthenticatedUser, "", p.ClientPlatform, "", r, "Authenticated via basic credentials in http auth header")
	}

	handler.ServeHTTPAuthenticated(w, r, host, ui.AuthenticatedUser)
}

var customPorts = make(map[int]*perUserProxy)
var customPortLock sync.RWMutex

func (c *config) openPerUserPorts() {
	for user, portInfo := range c.CustomPorts {
		customPortLock.RLock()
		p := customPorts[portInfo.Port]
		customPortLock.RUnlock()
		if p == nil {
			_, err := c.newPerUserProxy(user, portInfo)
			if err != nil {
				log.Printf("error opening per-user listener for %s: %v", user, err)
			}
		} else {
			p.expectedNetLock.Lock()
			p.ClientPlatform = portInfo.ClientPlatform
			p.expectedIPBlocks = p.expectedIPBlocks[:0]
			p.expectedNetLock.Unlock()
			for _, network := range portInfo.ExpectedNetworks {
				p.addExpectedNetwork(network)
			}
		}
	}
}

type portListEntry struct {
	User                 string
	Port                 int
	Platform             string
	AuthenticatedClients []string
	ExpectedNetworks     []string
}

func handlePerUserPortList(w http.ResponseWriter, r *http.Request) {
	entries := map[string]*portListEntry{}
	conf := getConfig()

	customPortLock.RLock()
	for _, p := range customPorts {
		var networks []string
		p.expectedNetLock.RLock()
		for d := range p.expectedDomains {
			networks = append(networks, d)
		}
		for _, nw := range p.expectedIPBlocks {
			networks = append(networks, nw.String())
		}
		clientPlatform := p.ClientPlatform
		p.expectedNetLock.RUnlock()

		user, ok := conf.UserForPort[p.Port]
		if !ok {
			continue
		}

		var authenticatedClients []string
		authCacheLock.RLock()
		for ip, u := range authCache[p.Port] {
			if u == user {
				authenticatedClients = append(authenticatedClients, ip)
			}
		}
		authCacheLock.RUnlock()

		entries[user] = &portListEntry{
			User:                 user,
			Port:                 p.Port,
			Platform:             clientPlatform,
			ExpectedNetworks:     networks,
			AuthenticatedClients: authenticatedClients,
		}
	}
	customPortLock.RUnlock()

	var data []*portListEntry
	for _, e := range entries {
		data = append(data, e)
	}

	ServeJSON(w, r, data)
}

func handlePerUserAuthenticate(w http.ResponseWriter, r *http.Request) {
	user := r.FormValue("user")
	if user == "" {
		http.Error(w, `You must specify which user to authenticate with the "user" form parameter.`, 400)
		return
	}
	conf := getConfig()
	port := conf.CustomPorts[user].Port
	if port == 0 {
		http.Error(w, user+" does not have a per-user proxy port set up.", 500)
		return
	}

	customPortLock.RLock()
	p := customPorts[port]
	customPortLock.RUnlock()
	if p == nil {
		http.Error(w, user+" does not have a per-user proxy port open.", 500)
		return
	}

	ip := r.FormValue("ip")
	if ip == "" {
		http.Error(w, `You must specify the client IP address with the "ip" form parameter.`, 400)
		return
	}

	p.AllowIP(ip)
	fmt.Fprintf(w, "Added authenticated IP address: (ip=%s, user=%s, port=%d)", ip, user, port)
	logAuthEvent("api-request", "correct", ip, port, user, "", "", "", r, "Authenticated via API call on behalf of device")
}

// authCache maps from local port and remote IP address to the authenticated username.
var authCache = map[int]map[string]string{}
var authCacheLock sync.RWMutex

// String is needed to implement starlark.Value.
func (p *perUserProxy) String() string {
	return fmt.Sprintf("CustomPort(%d)", p.Port)
}

// Type is needed to implement starlark.Value.
func (p *perUserProxy) Type() string {
	return "CustomPort"
}

// Freeze is needed to implement starlark.Value.
func (p *perUserProxy) Freeze() {}

// Hash is needed to implement starlark.Value.
func (p *perUserProxy) Hash() (uint32, error) {
	return 0, errors.New("unhashable type: CustomPort")
}

// Truth is needed to implement starlark.Value.
func (p *perUserProxy) Truth() starlark.Bool {
	return starlark.True
}

var customPortAttrNames = []string{"port", "user", "platform", "expected_networks"}

func (p *perUserProxy) AttrNames() []string {
	return customPortAttrNames
}

func (p *perUserProxy) Attr(name string) (starlark.Value, error) {
	switch name {
	case "port":
		return starlark.MakeInt(p.Port), nil
	case "user":
		return starlark.String(getConfig().UserForPort[p.Port]), nil
	case "platform":
		p.expectedNetLock.RLock()
		defer p.expectedNetLock.RUnlock()
		return starlark.String(p.ClientPlatform), nil
	case "expected_networks":
		p.expectedNetLock.RLock()
		defer p.expectedNetLock.RUnlock()
		var networks starlark.Tuple
		for d := range p.expectedDomains {
			networks = append(networks, starlark.String(d))
		}
		for _, b := range p.expectedIPBlocks {
			networks = append(networks, starlark.String(b.String()))
		}
		return networks, nil

	default:
		return nil, nil
	}
}
