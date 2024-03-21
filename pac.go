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

	"github.com/miekg/dns"

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
					p.AllowIP(clientIP(r))
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
	conf := getConfig()
	user, ok := conf.UserForPort[p.Port]
	if !ok {
		return
	}

	authCacheLock.Lock()
	authCache[authCacheKey{ip, p.Port}] = user
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
		// If a PTR record isn't available, fall back to SOA.
		host, _ = rdnsSOA(ip)
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

var dnsServer string

func init() {
	conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil || len(conf.Servers) == 0 {
		return
	}
	dnsServer = conf.Servers[0] + ":" + conf.Port
}

// rdnsSOA returns the nameserver from the SOA (start of authority) reverse-DNS
// record for ip.
func rdnsSOA(ip string) (server string, err error) {
	octets := strings.Split(ip, ".")
	if len(octets) != 4 {
		return "", errors.New("invalid IPv4 address")
	}
	octets[0], octets[1], octets[2], octets[3] = octets[3], octets[2], octets[1], octets[0]

	m := new(dns.Msg)

	for i := 0; i < 4; i++ {
		m.SetQuestion(strings.Join(octets[i:], ".")+".in-addr.arpa.", dns.TypeSOA)
		soa, err := dns.Exchange(m, dnsServer)
		if err != nil {
			return "", err
		}
		if soa.Rcode != dns.RcodeSuccess || len(soa.Answer) == 0 {
			continue
		}
		trsoa, ok := soa.Answer[0].(*dns.SOA)
		if !ok {
			continue
		}
		return trsoa.Ns, nil
	}

	return "", errors.New("SOA not found")
}

func (p *perUserProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conf := getConfig()
	configuredUser := conf.UserForPort[p.Port]
	handler := proxyHandler{
		user:      configuredUser,
		localPort: p.Port,
	}

	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	authCacheLock.RLock()
	cachedUser := authCache[authCacheKey{host, p.Port}]
	authCacheLock.RUnlock()

	if cachedUser == configuredUser {
		handler.ServeHTTP(w, r)
		return
	}

	// This client's IP address is not pre-authorized for this port, but
	// maybe it sent credentials and we can authorize it now.
	// We accept credentials in either the Proxy-Authorization header or
	// a URL parameter named "a".

	user, pass, ok := ProxyCredentials(r)
	if ok {
		switch {
		case user != configuredUser:
			logAuthEvent("custom port", "invalid", r.RemoteAddr, p.Port, user, pass, "", "", r, fmt.Sprint("Expected username ", configuredUser))
		case !conf.ValidCredentials(user, pass):
			logAuthEvent("custom port", "invalid", r.RemoteAddr, p.Port, user, pass, "", "", r, "Incorrect password")
		default:
			logAuthEvent("custom port", "correct", r.RemoteAddr, p.Port, user, "", "", "", r, "Authenticated via credentials in header and custom port")
			p.AllowIP(host)
			handler.ServeHTTP(w, r)
			return
		}
	}

	user, pass, ok = decodeBase64Credentials(r.FormValue("a"))
	if ok {
		switch {
		case user != configuredUser:
			logAuthEvent("url parameter", "invalid", r.RemoteAddr, p.Port, user, "", "", "", r, fmt.Sprint("Expected username ", configuredUser))
		case !conf.ValidCredentials(user, pass):
			logAuthEvent("url parameter", "invalid", r.RemoteAddr, p.Port, user, pass, "", "", r, "Incorrect password")
		default:
			logAuthEvent("url parameter", "correct", r.RemoteAddr, p.Port, user, "", "", "", r, "Authenticated via credentials in URL param and custom port")
			p.AllowIP(host)
			handler.ServeHTTP(w, r)
			return
		}
	}

	if conf.IPToUser[host] == configuredUser {
		p.AllowIP(host)
		handler.ServeHTTP(w, r)
		return
	}

	expectedNetwork := false
	ip := net.ParseIP(host)
	p.expectedNetLock.RLock()
	expectedPlatform := p.ClientPlatform
	for _, nw := range p.expectedIPBlocks {
		if nw.Contains(ip) {
			expectedNetwork = true
			break
		}
	}
	p.expectedNetLock.RUnlock()

	domain := rdnsDomain(host)
	if !expectedNetwork && domain != "" {
		p.expectedNetLock.RLock()
		expectedNetwork = p.expectedDomains[domain]
		p.expectedNetLock.RUnlock()
	}

	if expectedNetwork {
		derivedPlatform := platform(r.Header.Get("User-Agent"))
		if expectedPlatform != "" && derivedPlatform == expectedPlatform || darwinPlatforms[expectedPlatform] && derivedPlatform == "Darwin" {
			logAuthEvent("expected network", "correct", host, p.Port, configuredUser, "", derivedPlatform, domain, r, "Authenticated via expected platform and network")
			p.AllowIP(host)
			handler.ServeHTTP(w, r)
			return
		}
	}

	// Maybe this is a request where authentication isn't even required according
	// to the ACLs. Let it through, but don't mark it as
	// authenticated.
	// Leave checking for requre-auth ACLs to the main ServeHTTP method.
	handler.user = ""
	handler.ServeHTTP(w, r)
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
		entries[user] = &portListEntry{
			User:             user,
			Port:             p.Port,
			Platform:         clientPlatform,
			ExpectedNetworks: networks,
		}
	}
	customPortLock.RUnlock()

	authCacheLock.RLock()
	for k, user := range authCache {
		e := entries[user]
		if e != nil && e.User == user {
			e.AuthenticatedClients = append(e.AuthenticatedClients, k.remoteIP)
		}
	}
	authCacheLock.RUnlock()

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
	logAuthEvent("api request", "correct", ip, port, user, "", "", "", r, "Authenticated via API call on behalf of device")
}

type authCacheKey struct {
	remoteIP  string
	localPort int
}

// authCache maps from connection information to the authenticated username.
var authCache = map[authCacheKey]string{}
var authCacheLock sync.RWMutex
