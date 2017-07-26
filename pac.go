package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/miekg/dns"

	"golang.org/x/net/publicsuffix"
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
	User          string
	Port          int
	Handler       http.Handler
	allowedIPs    map[string]bool
	allowedIPLock sync.RWMutex

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
		User:            user,
		Port:            portInfo.Port,
		ClientPlatform:  portInfo.ClientPlatform,
		Handler:         proxyHandler{user: user},
		allowedIPs:      map[string]bool{},
		expectedDomains: map[string]bool{},
	}

	for _, network := range portInfo.ExpectedNetworks {
		p.addExpectedNetwork(network)
	}

	proxyForUserLock.Lock()
	proxyForUser[user] = p
	proxyForUserLock.Unlock()
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
	p.allowedIPLock.Lock()
	p.allowedIPs[ip] = true
	p.allowedIPLock.Unlock()
	log.Printf("Added IP address %s, authenticated as %s, on port %d", ip, p.User, p.Port)

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
		pf := platform(r.Header.Get("User-Agent"))
		if expectedPlatform != "" && pf == expectedPlatform || darwinPlatforms[expectedPlatform] && pf == "Darwin" {
			log.Printf("Authenticating %s as %s based on IP address and platform (domain=%s, platform=%s, user-agent=%q, port=%d)", host, p.User, domain, expectedPlatform, r.Header.Get("User-Agent"), p.Port)
			p.AllowIP(host)
			p.Handler.ServeHTTP(w, r)
			return
		}
	}

	// Maybe this is a request where authentication isn't even required according
	// to the ACLs. If so, let it through, but don't mark the IP address as
	// authenticated.
	tally := conf.URLRules.MatchingRules(r.URL)
	scores := conf.categoryScores(tally)
	reqACLs := conf.ACLs.requestACLs(r, "")
	thisRule, _ := conf.ChooseACLCategoryAction(reqACLs, scores, conf.Threshold, "allow", "require-auth")
	if thisRule.Action != "require-auth" {
		log.Printf("Allowing request in spite of missing authentication (url=%v, user=%s, port=%d, client=%s)", r.URL, p.User, p.Port, r.RemoteAddr)
		p.Handler.ServeHTTP(w, r)
		return
	}

	log.Printf("Missing required proxy authentication from %v to %v (User-Agent=%q, domain=%s, port=%d)", r.RemoteAddr, r.URL, r.Header.Get("User-Agent"), domain, p.Port)
	conf.send407(w)
}

var proxyForUser = make(map[string]*perUserProxy)
var proxyForUserLock sync.RWMutex

func (c *config) openPerUserPorts() {
	for user, portInfo := range c.CustomPorts {
		proxyForUserLock.RLock()
		p := proxyForUser[user]
		proxyForUserLock.RUnlock()
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
	var data []portListEntry

	proxyForUserLock.RLock()

	for _, p := range proxyForUser {
		var clients []string
		p.allowedIPLock.RLock()

		for c := range p.allowedIPs {
			clients = append(clients, c)
		}

		p.allowedIPLock.RUnlock()

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

		data = append(data, portListEntry{
			User:                 p.User,
			Port:                 p.Port,
			Platform:             clientPlatform,
			AuthenticatedClients: clients,
			ExpectedNetworks:     networks,
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
