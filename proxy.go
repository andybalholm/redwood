package main

import (
	"code.google.com/p/go.net/html/charset"
	"compress/gzip"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

var disableGzip = flag.Bool("disable-gzip", false, "Don't compress HTTP responses with gzip.")

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

	if len(r.URL.String()) > 10000 {
		http.Error(w, "URL too long", http.StatusRequestURITooLong)
		return
	}

	client := r.RemoteAddr
	host, _, err := net.SplitHostPort(client)
	if err == nil {
		client = host
	}
	user := client

	if h.user != "" {
		user = h.user
	} else if !*authNever && !h.TLS && (*authAlways || !lanAddress(client)) {
		u := authenticate(w, r)
		if u == "" {
			return
		}
		user = u
	}

	if r.Host == localServer {
		http.DefaultServeMux.ServeHTTP(w, r)
		return
	}

	if realHost, ok := virtualHosts[r.Host]; ok {
		r.Host = realHost
		r.URL.Host = realHost
	}

	if r.Method == "CONNECT" {
		if !tlsReady {
			sc := scorecard{
				tally: URLRules.MatchingRules(r.URL),
			}
			sc.calculate(user)
			logAccess(r, nil, sc, "", 0, false, user)
			if sc.action == BLOCK {
				showBlockPage(w, r, &sc, user)
				return
			}
		}

		conn, err := newHijackedConn(w)
		if err != nil {
			fmt.Fprintln(conn, "HTTP/1.1 500 Internal Server Error")
			fmt.Fprintln(conn)
			fmt.Fprintln(conn, err)
			conn.Close()
			return
		}
		fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		if tlsReady {
			SSLBump(conn, r.URL.Host, user)
		} else {
			connectDirect(conn, r.URL.Host, nil)
		}
		return
	}

	if r.Header.Get("Upgrade") == "websocket" {
		h.makeWebsocketConnection(w, r)
		return
	}

	r.Header.Add("Via", r.Proto+" Redwood")
	r.Header.Add("X-Forwarded-For", client)

	gzipOK := !*disableGzip && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip")
	r.Header.Del("Accept-Encoding")

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

	sc := scorecard{
		tally: URLRules.MatchingRules(r.URL),
	}
	sc.calculate(user)
	if sc.action == BLOCK {
		showBlockPage(w, r, &sc, user)
		logAccess(r, nil, sc, "", 0, false, user)
		return
	}

	urlChanged := changeQuery(r.URL)

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
		r.URL.Opaque = rawURL
	}

	var resp *http.Response
	if h.rt == nil {
		if r.URL.Opaque != "" && transport.Proxy != nil {
			if p, _ := transport.Proxy(r); p != nil {
				// If the request is going through a proxy, the host needs to be
				// included in the opaque element.
				r.URL.Opaque = "//" + r.URL.Host + r.URL.Opaque
			}
		}
		resp, err = transport.RoundTrip(r)
	} else {
		resp, err = h.rt.RoundTrip(r)
	}

	r.URL.Opaque = ""

	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		log.Printf("error fetching %s: %s", r.URL, err)
		logAccess(r, nil, sc, "", 0, false, user)
		return
	}
	defer resp.Body.Close()

	contentType, action := checkContentType(resp)

	switch action {
	case BLOCK:
		sc.action = BLOCK
		sc.blocked = []string{"blocked-mime"}
		showBlockPage(w, r, &sc, user)
		logAccess(r, resp, sc, contentType, 0, false, user)
		return

	case ALLOW:
		sc.action = IGNORE
		copyResponseHeader(w, resp)
		io.Copy(w, resp.Body)
		logAccess(r, resp, sc, contentType, 0, false, user)
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
		copyResponseHeader(w, resp)
		w.Write(content)
		n, err := io.Copy(w, resp.Body)
		if err != nil {
			log.Printf("error while copying response (URL: %s): %s", r.URL, err)
		}
		sc.action = IGNORE
		logAccess(r, resp, sc, contentType, int(n)+len(content), false, user)
		return
	}

	modified := false
	_, cs, _ := charset.DetermineEncoding(content, resp.Header.Get("Content-Type"))
	if strings.Contains(contentType, "html") {
		modified = pruneContent(r.URL, &content, cs)
		if modified {
			resp.Header.Set("Content-Type", "text/html; charset=utf-8")
			cs = "utf-8"
		}
	}

	scanContent(content, contentType, cs, sc.tally)
	sc.calculate(user)

	if sc.action == BLOCK {
		showBlockPage(w, r, &sc, user)
		logAccess(r, resp, sc, contentType, len(content), modified, user)
		return
	}

	if resp.Header.Get("Content-Type") == "" {
		// If the server didn't specify a content type, don't let the http
		// package add one by doing MIME sniffing.
		resp.Header.Set("Content-Type", "")
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

	logAccess(r, resp, sc, contentType, len(content), modified, user)
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
