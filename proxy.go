package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
)

type proxyHandler struct {
	// TLS is whether this is an HTTPS connection.
	TLS bool

	// connectPort is the server port that was specified in a CONNECT request.
	connectPort string
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
	client := r.RemoteAddr
	host, _, err := net.SplitHostPort(client)
	if err == nil {
		client = host
	}
	user := client

	if !h.TLS && !lanAddress(client) {
		u := authenticate(w, r)
		if u == "" {
			return
		}
		user = u
	}

	if r.Host == "203.0.113.1" {
		http.DefaultServeMux.ServeHTTP(w, r)
		return
	}

	if r.Method == "CONNECT" {
		if !tlsReady {
			sc := scorecard{
				tally: URLRules.MatchingRules(r.URL),
			}
			sc.calculate(user)
			if sc.action == BLOCK {
				showBlockPage(w, r, &sc)
				logAccess(r, nil, sc, "", 0, false, user)
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
			SSLBump(conn, r.URL.Host)
		} else {
			connectDirect(conn, r.URL.Host)
		}
		return
	}

	if r.Header.Get("Upgrade") == "websocket" {
		h.makeWebsocketConnection(w, r)
		return
	}

	r.Header.Add("Via", r.Proto+" Redwood")
	r.Header.Add("X-Forwarded-For", client)
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
		showBlockPage(w, r, &sc)
		logAccess(r, nil, sc, "", 0, false, user)
		return
	}

	changeQuery(r.URL)

	resp, err := transport.RoundTrip(r)
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
		showBlockPage(w, r, &sc)
		logAccess(r, resp, sc, contentType, 0, false, user)
		return

	case ALLOW:
		sc.action = IGNORE
		copyResponseHeader(w, resp)
		io.Copy(w, resp.Body)
		logAccess(r, resp, sc, contentType, 0, false, user)
		return
	}

	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("error while reading response body (URL: %s): %s", r.URL, err)
	}

	modified := false
	charset := findCharset(resp.Header.Get("Content-Type"), content)
	if strings.Contains(contentType, "html") {
		modified = pruneContent(r.URL, &content, charset)
		if modified {
			resp.Header.Set("Content-Type", "text/html; charset=utf-8")
			charset = "utf-8"
		}
	}

	scanContent(content, contentType, charset, sc.tally)
	sc.calculate(user)

	if sc.action == BLOCK {
		showBlockPage(w, r, &sc)
		logAccess(r, resp, sc, contentType, len(content), modified, user)
		return
	}

	copyResponseHeader(w, resp)
	w.Write(content)
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

// retryTransport is an http.RoundTripper that automatically retries
// failed GET and HEAD requests.
type retryTransport struct {
	http.Transport
}

var transport = retryTransport{
	http.Transport{
		TLSClientConfig: unverifiedClientConfig,
		Proxy:           http.ProxyFromEnvironment,
	},
}

func (t *retryTransport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	switch req.Method {
	case "GET", "HEAD":
		for i := 0; i < 3; i++ {
			resp, err = t.Transport.RoundTrip(req)
			if err == nil {
				return resp, err
			}
		}
		return nil, err
	}

	return t.Transport.RoundTrip(req)
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
