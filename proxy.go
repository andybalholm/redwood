package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
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

func (h proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Host == "203.0.113.1" {
		http.DefaultServeMux.ServeHTTP(w, r)
		return
	}

	if r.Method == "CONNECT" {
		if !tlsReady {
			http.Error(w, "This proxy server is not configured for HTTPS.", http.StatusMethodNotAllowed)
			return
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
		SSLBump(conn, r.URL.Host)
		return
	}

	r.Header.Add("Via", r.Proto+" Redwood")
	client := r.RemoteAddr
	host, _, err := net.SplitHostPort(client)
	if err == nil {
		client = host
	}
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
	sc.calculate(client)
	if sc.action == BLOCK {
		showBlockPage(w, r, &sc)
		logAccess(r, nil, sc, "", 0, false, client)
		return
	}

	changeQuery(r.URL)

	resp, err := unverifiedTransport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		logAccess(r, nil, sc, "", 0, false, client)
		return
	}
	defer resp.Body.Close()

	contentType, action := checkContentType(resp)

	switch action {
	case BLOCK:
		sc.action = BLOCK
		sc.blocked = []string{"blocked-mime"}
		showBlockPage(w, r, &sc)
		logAccess(r, resp, sc, contentType, 0, false, client)
		return

	case ALLOW:
		sc.action = IGNORE
		copyResponseHeader(w, resp)
		io.Copy(w, resp.Body)
		logAccess(r, resp, sc, contentType, 0, false, client)
		return
	}

	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(fmt.Errorf("error while reading response body: %s", err))
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
	sc.calculate(client)

	if sc.action == BLOCK {
		showBlockPage(w, r, &sc)
		logAccess(r, resp, sc, contentType, len(content), modified, client)
		return
	}

	copyResponseHeader(w, resp)
	w.Write(content)
	logAccess(r, resp, sc, contentType, len(content), modified, client)
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
	*bufio.ReadWriter
}

func (hc *hijackedConn) Read(b []byte) (int, error) {
	return hc.ReadWriter.Read(b)
}

func (hc *hijackedConn) Write(b []byte) (n int, err error) {
	n, err = hc.ReadWriter.Write(b)
	if err != nil {
		return
	}
	err = hc.ReadWriter.Flush()
	return
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
	return &hijackedConn{
		Conn:       conn,
		ReadWriter: bufrw,
	}, nil
}
