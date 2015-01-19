package main

import (
	"compress/gzip"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/html/charset"
)

type proxyHandler struct {
	// TLS is whether this is an HTTPS connection.
	TLS bool

	// connectPort is the server port that was specified in a CONNECT request.
	connectPort string

	// user is a user that has already been authenticated.
	user string

	// rt is the RoundTripper that will be used to fulfill the requests.
	// If it is nil, a default Transport will be used.
	rt http.RoundTripper
}

// lanAddress returns whether addr is in one of the LAN address ranges.
func lanAddress(addr string) bool {
	ip := net.ParseIP(addr)
	if ip4 := ip.To4(); ip4 != nil {
		switch ip4[0] {
		case 10, 127:
			return true
		case 172:
			return ip4[1]&0xf0 == 16
		case 192:
			return ip4[1] == 168
		}
		return false
	}

	if ip[0]&0xfe == 0xfc {
		return true
	}
	if ip[0] == 0xfe && (ip[1]&0xfc) == 0x80 {
		return true
	}

	return false
}

func (h proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	activeConnections.Add(1)
	defer activeConnections.Done()

	conf := getConfig()

	if !conf.ACLsLoaded {
		http.Error(w, "Redwood proxy configuration needs to be updated for this version of Redwood.\n(Use ACLs)", 500)
		return
	}

	if len(r.URL.String()) > 10000 {
		http.Error(w, "URL too long", http.StatusRequestURITooLong)
		return
	}

	if r.Header.Get("Proxy-Authorization") != "" {
		if !conf.ValidCredentials(ProxyCredentials(r)) {
			send407(w)
			return
		}
	}

	// Reconstruct the URL if it is incomplete (i.e. on a transparent proxy).
	if r.URL.Host == "" {
		r.URL.Host = r.Host
	}
	if r.URL.Scheme == "" {
		if h.TLS {
			r.URL.Scheme = "https"
		} else {
			r.URL.Scheme = "http"
		}
	}

	if realHost, ok := conf.VirtualHosts[r.Host]; ok {
		r.Host = realHost
		r.URL.Host = realHost
	}

	client := r.RemoteAddr
	host, _, err := net.SplitHostPort(client)
	if err == nil {
		client = host
	}
	user := client

	var authUser string
	if h.user != "" {
		authUser = h.user
	} else if u, _ := ProxyCredentials(r); u != "" {
		authUser = u
	}
	if authUser != "" {
		user = authUser
	}

	tally := conf.URLRules.MatchingRules(r.URL)
	scores := conf.categoryScores(tally)
	categories := conf.significantCategories(scores)

	reqACLs := conf.ACLs.requestACLs(r, authUser)

	possibleActions := []string{
		"allow",
		"block",
		"block-invisible",
	}
	if r.Header.Get("Proxy-Authorization") == "" && !h.TLS {
		possibleActions = append(possibleActions, "require-auth")
	}
	if r.Method == "CONNECT" && conf.TLSReady {
		possibleActions = append(possibleActions, "ssl-bump")
	}

	rule := conf.ChooseACLCategoryAction(reqACLs, categories, possibleActions...)
	if r.Method == "CONNECT" && conf.TLSReady && rule.Action == "" {
		// If the result is unclear, go ahead and start to bump the connection.
		// The ACLs will be checked one more time anyway.
		rule.Action = "ssl-bump"
	}

	switch rule.Action {
	case "require-auth":
		send407(w)
		return
	case "block":
		conf.showBlockPage(w, r, user, tally, scores, rule)
		logAccess(r, nil, 0, false, user, tally, scores, rule)
		return
	case "block-invisible":
		showInvisibleBlock(w)
		logAccess(r, nil, 0, false, user, tally, scores, rule)
		return
	case "ssl-bump":
		conn, err := newHijackedConn(w)
		if err != nil {
			fmt.Fprintln(conn, "HTTP/1.1 500 Internal Server Error")
			fmt.Fprintln(conn)
			fmt.Fprintln(conn, err)
			conn.Close()
			return
		}
		fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		SSLBump(conn, r.URL.Host, user, authUser)
		return
	}

	if r.Host == localServer {
		conf.ServeMux.ServeHTTP(w, r)
		return
	}

	if r.Method == "CONNECT" {
		conn, err := newHijackedConn(w)
		if err != nil {
			fmt.Fprintln(conn, "HTTP/1.1 500 Internal Server Error")
			fmt.Fprintln(conn)
			fmt.Fprintln(conn, err)
			conn.Close()
			return
		}
		fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		logAccess(r, nil, 0, false, user, tally, scores, rule)
		connectDirect(conn, r.URL.Host, nil)
		return
	}

	if r.Header.Get("Upgrade") == "websocket" {
		h.makeWebsocketConnection(w, r)
		return
	}

	r.Header.Add("Via", r.Proto+" Redwood")
	r.Header.Add("X-Forwarded-For", client)

	gzipOK := !conf.DisableGZIP && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") && !lanAddress(client)
	r.Header.Del("Accept-Encoding")

	urlChanged := conf.changeQuery(r.URL)

	if !urlChanged {
		// Rebuild the URL in a way that will preserve which characters are escaped
		// and which aren't, for compatibility with broken servers.
		rawURL := r.RequestURI
		if strings.HasPrefix(rawURL, r.URL.Scheme) {
			rawURL = rawURL[len(r.URL.Scheme):]
			rawURL = strings.TrimPrefix(rawURL, "://")
			slash := strings.Index(rawURL, "/")
			if slash == -1 {
				rawURL = "/"
			} else {
				rawURL = rawURL[slash:]
			}
		}
		q := strings.Index(rawURL, "?")
		if q != -1 {
			rawURL = rawURL[:q]
		}
		if strings.HasPrefix(rawURL, "//") {
			// The path should start with a single slash not two.
			rawURL = rawURL[1:]
		}
		r.URL.Opaque = rawURL
	}

	proxied := false
	var rt http.RoundTripper
	if h.rt == nil {
		if r.URL.Opaque != "" && transport.Proxy != nil {
			if p, _ := transport.Proxy(r); p != nil {
				// If the request is going through a proxy, the host needs to be
				// included in the opaque element.
				r.URL.Opaque = "//" + r.URL.Host + r.URL.Opaque
				proxied = true
			}
		}
		rt = &transport
	} else {
		rt = h.rt
	}

	if !proxied {
		r.Header.Del("Proxy-Authorization")
	}
	resp, err := rt.RoundTrip(r)
	r.URL.Opaque = ""

	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		log.Printf("error fetching %s: %s", r.URL, err)
		logAccess(r, nil, 0, false, user, tally, scores, rule)
		return
	}
	defer resp.Body.Close()

	originalContentType := resp.Header.Get("Content-Type")
	fixContentType(resp)

	respACLs := conf.ACLs.responseACLs(resp)
	acls := unionACLSets(reqACLs, respACLs)
	rule = conf.ChooseACLCategoryAction(acls, categories, "allow", "block", "block-invisible", "phrase-scan")
	if rule.Action == "" {
		rule.Action = "allow"
	}

	switch rule.Action {
	case "allow":
		resp.Header.Set("Content-Type", originalContentType)
		copyResponseHeader(w, resp)
		n, err := io.Copy(w, resp.Body)
		if err != nil {
			log.Printf("error while copying response (URL: %s): %s", r.URL, err)
		}
		logAccess(r, resp, int(n), false, user, tally, scores, rule)
		return
	case "block":
		conf.showBlockPage(w, r, user, tally, scores, rule)
		logAccess(r, resp, 0, false, user, tally, scores, rule)
		return
	case "block-invisible":
		showInvisibleBlock(w)
		logAccess(r, resp, 0, false, user, tally, scores, rule)
		return
	}

	lr := &io.LimitedReader{
		R: resp.Body,
		N: 1e7,
	}
	content, err := ioutil.ReadAll(lr)
	if err != nil {
		log.Printf("error while reading response body (URL: %s): %s", r.URL, err)
	}
	if lr.N == 0 {
		log.Println("response body too long to filter:", r.URL)
		resp.Header.Set("Content-Type", originalContentType)
		copyResponseHeader(w, resp)
		w.Write(content)
		n, err := io.Copy(w, resp.Body)
		if err != nil {
			log.Printf("error while copying response (URL: %s): %s", r.URL, err)
		}
		logAccess(r, resp, int(n)+len(content), false, user, tally, scores, ACLActionRule{Action: "allow", Needed: []string{"too-long-to-filter"}})
		return
	}

	contentType := resp.Header.Get("Content-Type")
	modified := false
	_, cs, _ := charset.DetermineEncoding(content, contentType)
	if strings.Contains(contentType, "html") {
		modified = conf.pruneContent(r.URL, &content, cs, acls)
		if modified {
			resp.Header.Set("Content-Type", "text/html; charset=utf-8")
			cs = "utf-8"
			resp.Header.Del("Content-Length")
		}
	}

	conf.scanContent(content, contentType, cs, tally)
	scores = conf.categoryScores(tally)
	categories = conf.significantCategories(scores)
	rule = conf.ChooseACLCategoryAction(acls, categories, "allow", "block", "block-invisible")
	if rule.Action == "" {
		rule.Action = "allow"
	}

	switch rule.Action {
	case "block":
		conf.showBlockPage(w, r, user, tally, scores, rule)
		logAccess(r, resp, len(content), modified, user, tally, scores, rule)
		return
	case "block-invisible":
		showInvisibleBlock(w)
		logAccess(r, resp, len(content), modified, user, tally, scores, rule)
		return
	}

	if !modified {
		resp.Header.Set("Content-Type", originalContentType)
	}

	if gzipOK && len(content) > 1000 {
		resp.Header.Set("Content-Encoding", "gzip")
		resp.Header.Del("Content-Length")
		copyResponseHeader(w, resp)
		gzw := gzip.NewWriter(w)
		gzw.Write(content)
		gzw.Close()
	} else {
		copyResponseHeader(w, resp)
		w.Write(content)
	}

	logAccess(r, resp, len(content), modified, user, tally, scores, rule)
}

// copyResponseHeader writes resp's header and status code to w.
func copyResponseHeader(w http.ResponseWriter, resp *http.Response) {
	newHeader := w.Header()
	for key, values := range resp.Header {
		for _, v := range values {
			newHeader.Add(key, v)
		}
	}

	w.WriteHeader(resp.StatusCode)
}

// A hijackedConn is a connection that has been hijacked (to fulfill a CONNECT
// request).
type hijackedConn struct {
	net.Conn
	io.Reader
}

func (hc *hijackedConn) Read(b []byte) (int, error) {
	return hc.Reader.Read(b)
}

func newHijackedConn(w http.ResponseWriter) (*hijackedConn, error) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("connection doesn't support hijacking")
	}
	conn, bufrw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	err = bufrw.Flush()
	if err != nil {
		return nil, err
	}
	return &hijackedConn{
		Conn:   conn,
		Reader: bufrw.Reader,
	}, nil
}

var transport = http.Transport{
	TLSClientConfig: unverifiedClientConfig,
	Proxy:           http.ProxyFromEnvironment,
}

// This is to deal with the problem of stale keepalive connections, which cause
// transport.RoundTrip to return io.EOF.
func init() {
	go func() {
		for _ = range time.Tick(10 * time.Second) {
			transport.CloseIdleConnections()
		}
	}()

	transport.RegisterProtocol("ftp", FTPTransport{})
}

func (h proxyHandler) makeWebsocketConnection(w http.ResponseWriter, r *http.Request) {
	addr := r.Host
	if _, _, err := net.SplitHostPort(addr); err != nil {
		// There is no port specified; we need to add it.
		port := h.connectPort
		if port == "" {
			port = "80"
		}
		addr = net.JoinHostPort(addr, port)
	}
	var err error
	var serverConn net.Conn
	if h.TLS {
		serverConn, err = tls.Dial("tcp", addr, unverifiedClientConfig)
	} else {
		serverConn, err = net.Dial("tcp", addr)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = r.Write(serverConn)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Couldn't create a websocket connection", http.StatusInternalServerError)
		return
	}
	conn, bufrw, err := hj.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	go func() {
		io.Copy(conn, serverConn)
		conn.Close()
	}()
	io.Copy(serverConn, bufrw)
	serverConn.Close()
	return
}
