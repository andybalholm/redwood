package main

import (
	"bytes"
	"compress/flate"
	"crypto/tls"
	"errors"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"io/ioutil"
	"log"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/andybalholm/cascadia"
	"github.com/andybalholm/dhash"
	"github.com/klauspost/compress/gzip"
	"golang.org/x/net/html"
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

var ip6Loopback = net.ParseIP("::1")

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

	// IPv6
	switch {
	case ip[0]&0xfe == 0xfc:
		return true
	case ip[0] == 0xfe && (ip[1]&0xfc) == 0x80:
		return true
	case ip.Equal(ip6Loopback):
		return true
	}

	return false
}

var titleSelector = cascadia.MustCompile("title")

func (h proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	activeConnections.Add(1)
	defer activeConnections.Done()

	// If a request is directed to Redwood, rather than proxied or intercepted,
	// it should be handled as an API request.
	if !h.TLS && r.URL.Host == "" && strings.Contains(r.Host, ":") {
		handleAPI(w, r)
		return
	}

	conf := getConfig()

	if len(r.URL.String()) > 10000 {
		http.Error(w, "URL too long", http.StatusRequestURITooLong)
		return
	}

	client := r.RemoteAddr
	host, _, err := net.SplitHostPort(client)
	if err == nil {
		client = host
	}

	authUser := ""

	switch {
	case h.user != "":
		authUser = h.user

	case r.Header.Get("Proxy-Authorization") != "":
		user, pass, ok := ProxyCredentials(r)
		if ok {
			if conf.ValidCredentials(user, pass) {
				authUser = user
			} else {
				log.Printf("Incorrect username or password from %v: %s:%s", r.RemoteAddr, user, pass)
			}
		} else {
			log.Printf("Invalid Proxy-Authorization header from %v: %q", r.RemoteAddr, r.Header.Get("Proxy-Authorization"))
		}
	}

	// Reconstruct the URL if it is incomplete (i.e. on a transparent proxy).
	if r.URL.Scheme == "" {
		if h.TLS {
			r.URL.Scheme = "https"
		} else {
			r.URL.Scheme = "http"
		}
	}
	if r.URL.Host == "" {
		if r.Host != "" {
			r.URL.Host = r.Host
		} else {
			log.Printf("Request from %s has no host in URL: %v", client, r.URL)
			// Delay a while since some programs really hammer us with this kind of request.
			time.Sleep(time.Second)
			http.Error(w, "No host in request URL, and no Host header.", http.StatusBadRequest)
			return
		}
	}

	if realHost, ok := conf.VirtualHosts[r.Host]; ok {
		r.Host = realHost
		r.URL.Host = realHost
	}

	user := client
	if authUser != "" {
		user = authUser
	}

	// Handle IPv6 hostname without brackets in CONNECT request.
	if r.Method == "CONNECT" {
		hostport := r.URL.Host
		host, port, err := net.SplitHostPort(hostport)
		if err, ok := err.(*net.AddrError); ok && err.Err == "too many colons in address" {
			colon := strings.LastIndex(hostport, ":")
			host, port = hostport[:colon], hostport[colon+1:]
			if ip := net.ParseIP(host); ip != nil {
				r.URL.Host = net.JoinHostPort(host, port)
			}
		}
	}

	// Some proxy interception programs send HTTP traffic as CONNECT requests
	// for port 80.
	if _, port, err := net.SplitHostPort(r.URL.Host); err == nil && port == "80" && r.Method == "CONNECT" {
		conn, err := newHijackedConn(w)
		if err != nil {
			log.Println("Error hijacking connection for CONNECT request to %s: %v", r.URL.Host, err)
			return
		}
		fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")

		server := &http.Server{
			Handler: proxyHandler{
				TLS:         false,
				connectPort: port,
				user:        authUser,
				rt:          h.rt,
			},
			IdleTimeout: conf.CloseIdleConnections,
		}
		conf = nil // Allow it to be garbage-collected, since we won't use it any more.
		server.Serve(&singleListener{conn: conn})
		return
	}

	tally := conf.URLRules.MatchingRules(r.URL)
	scores := conf.categoryScores(tally)
	reqScores := scores

	reqACLs := conf.ACLs.requestACLs(r, authUser)

	possibleActions := []string{
		"allow",
		"block",
		"block-invisible",
	}
	if authUser == "" && !h.TLS {
		possibleActions = append(possibleActions, "require-auth")
	}
	if r.Method == "CONNECT" && conf.TLSReady {
		possibleActions = append(possibleActions, "ssl-bump")
	}

	thisRule, ignored := conf.ChooseACLCategoryAction(reqACLs, scores, conf.Threshold, possibleActions...)
	if r.Method == "CONNECT" && conf.TLSReady && thisRule.Action == "" {
		// If the result is unclear, go ahead and start to bump the connection.
		// The ACLs will be checked one more time anyway.
		thisRule.Action = "ssl-bump"
	}

	switch thisRule.Action {
	case "require-auth":
		conf.send407(w)
		log.Printf("Missing required proxy authentication from %v to %v", r.RemoteAddr, r.URL)
		return
	case "block":
		conf.showBlockPage(w, r, nil, user, tally, scores, thisRule)
		logAccess(r, nil, 0, false, user, tally, scores, thisRule, "", ignored)
		return
	case "block-invisible":
		showInvisibleBlock(w)
		logAccess(r, nil, 0, false, user, tally, scores, thisRule, "", ignored)
		return
	case "ssl-bump":
		conn, err := newHijackedConn(w)
		if err != nil {
			log.Println("Error hijacking connection for CONNECT request to %s: %v", r.URL.Host, err)
			return
		}
		fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		conf = nil // Allow it to be garbage-collected, since we won't use it any more.
		SSLBump(conn, r.URL.Host, user, authUser, r)
		return
	}

	if r.Host == localServer {
		logAccess(r, nil, 0, false, user, tally, scores, thisRule, "", ignored)
		conf.ServeMux.ServeHTTP(w, r)
		return
	}

	if r.Method == "CONNECT" {
		conn, err := newHijackedConn(w)
		if err != nil {
			log.Println("Error hijacking connection for CONNECT request to %s: %v", r.URL.Host, err)
			return
		}
		fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		logAccess(r, nil, 0, false, user, tally, scores, thisRule, "", ignored)
		conf = nil // Allow it to be garbage-collected, since we won't use it any more.
		connectDirect(conn, r.URL.Host, nil)
		return
	}

	if r.Header.Get("Upgrade") == "websocket" {
		logAccess(r, nil, 0, false, user, tally, scores, thisRule, "", ignored)
		h.makeWebsocketConnection(w, r)
		return
	}

	if len(r.Header["X-Forwarded-For"]) >= 10 {
		http.Error(w, "Proxy forwarding loop", http.StatusBadRequest)
		log.Printf("Proxy forwarding loop from %s to %v", r.Header.Get("X-Forwarded-For"), r.URL)
		return
	}

	headerRule, _ := conf.ChooseACLCategoryAction(reqACLs, scores, conf.Threshold, "disable-proxy-headers")
	if headerRule.Action != "disable-proxy-headers" {
		viaHosts := r.Header["Via"]
		viaHosts = append(viaHosts, strings.TrimPrefix(r.Proto, "HTTP/")+" Redwood")
		r.Header.Set("Via", strings.Join(viaHosts, ", "))
		r.Header.Add("X-Forwarded-For", client)
	}

	gzipOK := !conf.DisableGZIP && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") && !lanAddress(client)
	r.Header.Del("Accept-Encoding")

	conf.changeQuery(r.URL)

	var rt http.RoundTripper
	if h.rt == nil {
		rt = httpTransport
	} else {
		rt = h.rt
	}

	// Some HTTP/2 servers don't like having a body on a GET request, even if
	// it is empty.
	if r.ContentLength == 0 {
		r.Body.Close()
		r.Body = nil
	}

	removeHopByHopHeaders(r.Header)
	resp, err := rt.RoundTrip(r)

	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		log.Printf("error fetching %s: %s", r.URL, err)
		logAccess(r, nil, 0, false, user, tally, scores, thisRule, "", ignored)
		return
	}
	defer resp.Body.Close()

	if resp.Header.Get("Content-Encoding") == "deflate" && r.Method != "HEAD" {
		resp.Body = flate.NewReader(resp.Body)
		defer resp.Body.Close()
		resp.Header.Del("Content-Encoding")
		resp.Header.Del("Content-Length")
		resp.ContentLength = -1
	}

	// Prevent switching to QUIC.
	resp.Header.Del("Alternate-Protocol")
	resp.Header.Del("Alt-Svc")

	removeHopByHopHeaders(resp.Header)

	respACLs := conf.ACLs.responseACLs(resp)
	acls := unionACLSets(reqACLs, respACLs)

	headerRule, _ = conf.ChooseACLCategoryAction(acls, scores, conf.Threshold, "disable-proxy-headers")
	if headerRule.Action != "disable-proxy-headers" {
		viaHosts := resp.Header["Via"]
		viaHosts = append(viaHosts, strings.TrimPrefix(resp.Proto, "HTTP/")+" Redwood")
		resp.Header.Set("Via", strings.Join(viaHosts, ", "))
	}

	if r.Method == "HEAD" {
		thisRule, ignored = conf.ChooseACLCategoryAction(acls, scores, conf.Threshold, "allow", "block", "block-invisible")
	} else {
		thisRule, ignored = conf.ChooseACLCategoryAction(acls, scores, conf.Threshold, "allow", "block", "block-invisible", "hash-image", "phrase-scan")
	}
	if thisRule.Action == "" {
		thisRule.Action = "allow"
	}

	gzipOK = gzipOK && resp.Header.Get("Content-Encoding") == "" && resp.Header.Get("Content-Type") != ""

	switch thisRule.Action {
	case "allow":
		var dest io.Writer = w
		shouldGZIP := false
		if gzipOK && (resp.ContentLength == -1 || resp.ContentLength > 1024) {
			ct, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
			if err == nil {
				switch ct {
				case "application/javascript", "application/x-javascript", "application/json":
					shouldGZIP = true
				default:
					shouldGZIP = strings.HasPrefix(ct, "text/")
				}
			}
		}
		if shouldGZIP {
			resp.Header.Set("Content-Encoding", "gzip")
			gzw := gzip.NewWriter(w)
			defer gzw.Close()
			dest = gzw
		} else if resp.ContentLength > 0 {
			w.Header().Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
		}
		copyResponseHeader(w, resp)
		n, err := io.Copy(dest, resp.Body)
		if err != nil {
			log.Printf("error while copying response (URL: %s): %s", r.URL, err)
		}
		logAccess(r, resp, int(n), false, user, tally, scores, thisRule, "", ignored)
		return
	case "block":
		conf.showBlockPage(w, r, resp, user, tally, scores, thisRule)
		logAccess(r, resp, 0, false, user, tally, scores, thisRule, "", ignored)
		return
	case "block-invisible":
		showInvisibleBlock(w)
		logAccess(r, resp, 0, false, user, tally, scores, thisRule, "", ignored)
		return
	}

	lr := &io.LimitedReader{
		R: resp.Body,
		N: int64(conf.MaxContentScanSize),
	}
	content, err := ioutil.ReadAll(lr)
	if err != nil {
		log.Printf("error while reading response body (URL: %s): %s", r.URL, err)
	}
	if lr.N == 0 {
		log.Println("response body too long to filter:", r.URL)
		var dest io.Writer = w
		if gzipOK {
			resp.Header.Set("Content-Encoding", "gzip")
			gzw := gzip.NewWriter(w)
			defer gzw.Close()
			dest = gzw
		} else if resp.ContentLength > 0 {
			w.Header().Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
		}
		copyResponseHeader(w, resp)
		dest.Write(content)
		n, err := io.Copy(dest, resp.Body)
		if err != nil {
			log.Printf("error while copying response (URL: %s): %s", r.URL, err)
		}
		logAccess(r, resp, int(n)+len(content), false, user, tally, scores, ACLActionRule{Action: "allow", Needed: []string{"too-long-to-filter"}}, "", ignored)
		return
	}

	modified := false
	pageTitle := ""

	switch thisRule.Action {
	case "phrase-scan":
		contentType := resp.Header.Get("Content-Type")
		_, cs, _ := charset.DetermineEncoding(content, contentType)
		var doc *html.Node
		if strings.Contains(contentType, "html") {
			if conf.LogTitle {
				doc, err = parseHTML(content, cs)
				if err != nil {
					log.Printf("Error parsing HTML from %s: %s", r.URL, err)
				} else {
					t := titleSelector.MatchFirst(doc)
					if t != nil {
						if titleText := t.FirstChild; titleText != nil && titleText.Type == html.TextNode {
							pageTitle = titleText.Data
						}
					}
				}
			}

			modified = conf.pruneContent(r.URL, &content, cs, &doc)
			if modified {
				cs = "utf-8"
			}
		}

		conf.scanContent(content, contentType, cs, tally)

		if strings.Contains(contentType, "html") {
			aclsWithCategories := copyACLSet(acls)
			for name, score := range reqScores {
				if conf.Categories[name].action == ACL && score > 0 {
					aclsWithCategories[name] = true
				}
			}
			modifiedAfterScan := conf.doFilteredPruning(r.URL, content, cs, aclsWithCategories, &doc)

			censorRule, _ := conf.ChooseACLCategoryAction(acls, scores, conf.Threshold, "censor-words")
			if censorRule.Action == "censor-words" {
				if doc == nil {
					doc, _ = parseHTML(content, cs)
				}
				if censorHTML(doc, conf.CensoredWords) {
					modifiedAfterScan = true
				}
			}

			if modifiedAfterScan {
				b := new(bytes.Buffer)
				if err := html.Render(b, doc); err != nil {
					log.Printf("Error rendering modified content from %s: %v", r.URL, err)
				} else {
					content = b.Bytes()
					modified = true
				}
			}
			if modified {
				resp.Header.Set("Content-Type", "text/html; charset=utf-8")
			}
		}

	case "hash-image":
		img, _, err := image.Decode(bytes.NewReader(content))
		if err != nil {
			log.Printf("Error decoding image from %v: %v", r.URL, err)
			break
		}
		hash := dhash.New(img)

		for _, h := range conf.ImageHashes {
			distance := dhash.Distance(hash, h.Hash)
			if distance <= h.Threshold || h.Threshold == -1 && distance <= conf.DhashThreshold {
				tally[rule{imageHash, h.String()}]++
			}
		}
	}

	scores = conf.categoryScores(tally)
	thisRule, ignored = conf.ChooseACLCategoryAction(acls, scores, conf.Threshold, "allow", "block", "block-invisible")
	if thisRule.Action == "" {
		thisRule.Action = "allow"
	}

	switch thisRule.Action {
	case "block":
		conf.showBlockPage(w, r, resp, user, tally, scores, thisRule)
		logAccess(r, resp, len(content), modified, user, tally, scores, thisRule, pageTitle, ignored)
		return
	case "block-invisible":
		showInvisibleBlock(w)
		logAccess(r, resp, len(content), modified, user, tally, scores, thisRule, pageTitle, ignored)
		return
	}

	if gzipOK && len(content) > 1000 {
		resp.Header.Set("Content-Encoding", "gzip")
		copyResponseHeader(w, resp)
		gzw := gzip.NewWriter(w)
		gzw.Write(content)
		gzw.Close()
	} else {
		w.Header().Set("Content-Length", strconv.Itoa(len(content)))
		copyResponseHeader(w, resp)
		w.Write(content)
	}

	logAccess(r, resp, len(content), modified, user, tally, scores, thisRule, pageTitle, ignored)
}

// copyResponseHeader writes resp's header and status code to w.
func copyResponseHeader(w http.ResponseWriter, resp *http.Response) {
	newHeader := w.Header()
	for key, values := range resp.Header {
		if key == "Content-Length" {
			continue
		}
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
		conn.Close()
		return nil, err
	}
	return &hijackedConn{
		Conn:   conn,
		Reader: bufrw.Reader,
	}, nil
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

	// Some servers are very particular about the
	// capitalization of the special WebSocket headers.
	for k, v := range r.Header {
		if strings.HasPrefix(k, "Sec-Websocket-") {
			newKey := "Sec-WebSocket-" + strings.TrimPrefix(k, "Sec-Websocket-")
			delete(r.Header, k)
			r.Header[newKey] = v
		}
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

var hopByHop = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"TE",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// removeHopByHopHeaders removes header fields listed in
// http://tools.ietf.org/html/draft-ietf-httpbis-p1-messaging-14#section-7.1.3.1
func removeHopByHopHeaders(h http.Header) {
	toRemove := hopByHop
	if c := h.Get("Connection"); c != "" {
		for _, key := range strings.Split(c, ",") {
			toRemove = append(toRemove, strings.TrimSpace(key))
		}
	}
	for _, key := range toRemove {
		h.Del(key)
	}
}

// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections. It's used by ListenAndServe and ListenAndServeTLS so
// dead TCP connections (e.g. closing laptop mid-download) eventually
// go away. (Copied from net/http package)
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	return tc, nil
}
