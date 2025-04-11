package main

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	_ "image/gif"
	"image/jpeg"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"io/ioutil"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/andybalholm/cascadia"
	"github.com/andybalholm/dhash"
	"github.com/baruwa-enterprise/clamd"
	"github.com/dustmop/soup"
	"github.com/golang/gddo/httputil"
	"github.com/golang/gddo/httputil/header"
	"github.com/klauspost/compress/gzip"
	"github.com/qri-io/starlib/bsoup"
	"go.starlark.net/starlark"
	"golang.org/x/image/draw"
	_ "golang.org/x/image/webp"
	"golang.org/x/net/html"
	"golang.org/x/net/html/charset"
)

type proxyHandler struct {
	// TLS is whether this is an HTTPS connection.
	TLS bool

	// tlsFingerprint is the JA3 TLS fingerprint of the client (if available).
	tlsFingerprint string

	// connectPort is the server port that was specified in a CONNECT request.
	connectPort string

	// user is a user that has already been authenticated.
	user string

	// localPort is the TCP port that this proxyHandler is receiving requests on.
	localPort int

	// rt is the RoundTripper that will be used to fulfill the requests.
	// If it is nil, a default Transport will be used.
	rt http.RoundTripper

	// session is the TLSSession object, if this is an SSLBumped connection,
	// or nil otherwise.
	session *TLSSession
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

	client := r.RemoteAddr
	host, _, err := net.SplitHostPort(client)
	if err == nil {
		client = host
	}

	// Don't look for authentication if the session is already authenticated,
	// or if it's already SSLBumped.
	if h.user != "" || h.TLS {
		h.ServeHTTPAuthenticated(w, r, client, h.user)
		return
	}

	ui := &UserInfo{
		Request: r,
	}
	ui.Authenticate(nil)

	h.ServeHTTPAuthenticated(w, r, ui.ClientIP, ui.AuthenticatedUser)
}

// ServeHTTPAuthenticated performs the part of serving a proxy request that
// happens after the user is authenticated. (If no user successfully authenticated,
// authUser may be empty.)
func (h proxyHandler) ServeHTTPAuthenticated(w http.ResponseWriter, r *http.Request, client, authUser string) {
	user := client
	if authUser != "" {
		user = authUser
	}

	if len(r.URL.String()) > 10000 {
		http.Error(w, "URL too long", http.StatusRequestURITooLong)
		return
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

	if realHost, ok := getConfig().VirtualHosts[r.Host]; ok {
		r.Host = realHost
		r.URL.Host = realHost
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
			log.Printf("Error hijacking connection for CONNECT request to %s: %v", r.URL.Host, err)
			panic(http.ErrAbortHandler)
		}
		fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")

		server := &http.Server{
			Handler: proxyHandler{
				TLS:         false,
				connectPort: port,
				user:        authUser,
				rt:          h.rt,
			},
			IdleTimeout: getConfig().CloseIdleConnections,
		}
		server.Serve(&singleListener{conn: conn})
		return
	}

	if h.tlsFingerprint != "" {
		r = r.WithContext(context.WithValue(r.Context(), tlsFingerprintKey{}, h.tlsFingerprint))
	}

	request := &Request{
		Request:      r,
		User:         authUser,
		LocalPort:    h.localPort,
		ExpectedUser: getConfig().UserForPort[h.localPort],
		ClientIP:     client,
		Session:      h.session,
	}

	filterRequest(request, !h.TLS)

	if request.Action.Action == "require-auth" {
		send407(w)
		logAuthEvent("proxy-auth-header", "missing", r.RemoteAddr, h.localPort, "", "", "", "", r, "Missing required proxy authentication")
		return
	}

	if r.Method == "CONNECT" && getConfig().TLSReady {
		// SSLBump takes priority overy any action besides require-auth, because showing a block page
		// doesn't work till after the connection is bumped.
		conn, err := newHijackedConn(w)
		if err != nil {
			log.Printf("Error hijacking connection for CONNECT request to %s: %v", r.URL.Host, err)
			panic(http.ErrAbortHandler)
		}
		fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		SSLBump(conn, r.URL.Host, user, authUser, r)
		return
	}

	switch request.Action.Action {
	case "block":
		showBlockPage(w, r, nil, user, request.Tally, request.Scores.data, request.Action, request.LogData)
		logAccess(r, nil, 0, false, user, request.Tally, request.Scores.data, request.Action, "", request.Ignored, nil, request.LogData)
		return
	case "block-invisible":
		showInvisibleBlock(w)
		logAccess(r, nil, 0, false, user, request.Tally, request.Scores.data, request.Action, "", request.Ignored, nil, request.LogData)
		return
	}

	if r.Host == localServer {
		logAccess(r, nil, 0, false, user, request.Tally, request.Scores.data, request.Action, "", request.Ignored, nil, request.LogData)
		getConfig().ServeMux.ServeHTTP(w, r)
		return
	}

	if r.Method == "CONNECT" {
		// …and not TLSReady
		conn, err := newHijackedConn(w)
		if err != nil {
			log.Printf("Error hijacking connection for CONNECT request to %s: %v", r.URL.Host, err)
			panic(http.ErrAbortHandler)
		}
		fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		logAccess(r, nil, 0, false, user, request.Tally, request.Scores.data, request.Action, "", request.Ignored, nil, request.LogData)
		connectDirect(conn, r.URL.Host, nil, dialer)
		return
	}

	if r.Header.Get("Upgrade") == "websocket" {
		logAccess(r, nil, 0, false, user, request.Tally, request.Scores.data, request.Action, "", request.Ignored, nil, request.LogData)
		h.makeWebsocketConnection(w, r)
		return
	}

	if len(r.Header["X-Forwarded-For"]) >= 10 {
		w.Header().Set("Connection", "close")
		http.Error(w, "Proxy forwarding loop", http.StatusBadRequest)
		log.Printf("Proxy forwarding loop from %s to %v", r.Header.Get("X-Forwarded-For"), r.URL)
		return
	}

	{
		conf := getConfig()
		headerRule, _ := conf.ChooseACLCategoryAction(request.ACLs.data, request.Scores.data, conf.Threshold, "disable-proxy-headers")
		if headerRule.Action != "disable-proxy-headers" {
			viaHosts := r.Header["Via"]
			viaHosts = append(viaHosts, strings.TrimPrefix(r.Proto, "HTTP/")+" Redwood")
			r.Header.Set("Via", strings.Join(viaHosts, ", "))
			r.Header.Add("X-Forwarded-For", client)
		}
	}

	// Limit Accept-Encoding header to encodings we can handle.
	acceptEncoding := header.ParseAccept(r.Header, "Accept-Encoding")
	filteredEncodings := make([]header.AcceptSpec, 0, len(acceptEncoding))
	for _, a := range acceptEncoding {
		switch a.Value {
		case "br", "gzip", "deflate":
			filteredEncodings = append(filteredEncodings, a)
		}
	}
	switch {
	case len(filteredEncodings) == 0:
		r.Header.Del("Accept-Encoding")
	case len(filteredEncodings) != len(acceptEncoding):
		specs := make([]string, len(filteredEncodings))
		for i, a := range filteredEncodings {
			if a.Q == 1 {
				specs[i] = a.Value
			} else {
				specs[i] = fmt.Sprintf("%s;q=%f", a.Value, a.Q)
			}
		}
		r.Header.Set("Accept-Encoding", strings.Join(specs, ", "))
	}

	getConfig().changeQuery(r.URL)

	var rt http.RoundTripper
	switch {
	case r.URL.Scheme == "ftp":
		rt = FTPTransport{}
	case request.hostChanged:
		rt = transportWithExtraRootCerts
	case h.rt != nil:
		rt = h.rt
	default:
		rt = transportWithExtraRootCerts
	}

	// Some HTTP/2 servers don't like having a body on a GET request, even if
	// it is empty.
	if r.ContentLength == 0 {
		r.Body.Close()
		r.Body = nil
	}

	removeHopByHopHeaders(r.Header)
	resp, err := rt.RoundTrip(r)

	if err == context.Canceled {
		return
	}
	if err != nil {
		showErrorPage(w, r, err)
		log.Printf("error fetching %s: %s", r.URL, err)
		logAccess(r, nil, 0, false, user, request.Tally, request.Scores.data, request.Action, "", request.Ignored, nil, request.LogData)
		return
	}
	defer resp.Body.Close()

	// Prevent switching to QUIC.
	resp.Header.Del("Alternate-Protocol")
	resp.Header.Del("Alt-Svc")

	removeHopByHopHeaders(resp.Header)

	// This was a workaround for https://github.com/golang/go/issues/31753,
	// which has been fixed. But it's also needed to protect our own content sniffing in acl.go.
	if resp.Header.Get("Content-Type") == "" && resp.Header.Get("Content-Encoding") == "gzip" && r.Method != "HEAD" {
		gzr, err := gzip.NewReader(resp.Body)
		if err != nil {
			log.Printf("Error creating gzip reader for %v: %v", r.URL, err)
		} else {
			resp.Body = gzr
			resp.Header.Del("Content-Encoding")
		}
	}

	response := &Response{
		Request:  request,
		Response: resp,
		LogData:  request.LogData,
	}
	response.Scores = request.Scores
	response.Tally = make(map[rule]int)
	for k, v := range request.Tally {
		response.Tally[k] = v
	}

	var scanAction ACLActionRule
	{
		conf := getConfig()
		respACLs := conf.ACLs.responseACLs(resp)
		response.ACLs.data = unionACLSets(request.ACLs.data, respACLs)

		headerRule, _ := conf.ChooseACLCategoryAction(response.ACLs.data, response.Scores.data, conf.Threshold, "disable-proxy-headers")
		if headerRule.Action != "disable-proxy-headers" {
			viaHosts := resp.Header["Via"]
			viaHosts = append(viaHosts, strings.TrimPrefix(resp.Proto, "HTTP/")+" Redwood")
			resp.Header.Set("Via", strings.Join(viaHosts, ", "))
		}

		var possibleActions []string
		if r.Method != "HEAD" {
			possibleActions = append(possibleActions, "hash-image", "phrase-scan")
			if conf.ClamAV != nil {
				possibleActions = append(possibleActions, "virus-scan")
			}
		}

		scanAction, _ = conf.ChooseACLCategoryAction(response.ACLs.data, response.Scores.data, conf.Threshold, possibleActions...)
	}

	switch scanAction.Action {
	case "phrase-scan":
		if err := doPhraseScan(response); err != nil {
			showErrorPage(w, r, err)
			return
		}

	case "hash-image":
		if err := doImageHash(response); err != nil {
			showErrorPage(w, r, err)
			return
		}

	case "virus-scan":
		if err := doVirusScan(response); err != nil {
			showErrorPage(w, r, err)
			return
		}
		if response.Action.Action == "block" {
			showBlockPage(w, r, resp, user, response.Tally, response.Scores.data, response.Action, response.LogData)
			logAccess(r, resp, response.Response.ContentLength, false, user, response.Tally, response.Scores.data, response.Action, "", nil, response.ClamdResponses(), response.LogData)
			return
		}
	}

	response.Scores.data = getConfig().categoryScores(response.Tally)

	contentRule, _ := getConfig().ChooseACLCategoryAction(response.ACLs.data, response.Scores.data, 1, "log-content")
	if contentRule.Action == "log-content" {
		content, _ := response.Content(math.MaxInt)
		if content != nil {
			logContent(r.URL, content, response.Scores.data)
		}
	}

	response.PossibleActions = []string{"allow", "block", "block-invisible"}
	callStarlarkFunctions("filter_response", response)

	response.chooseAction()

	switch response.Action.Action {
	case "block":
		showBlockPage(w, r, resp, user, response.Tally, response.Scores.data, response.Action, response.LogData)
		logAccess(r, resp, 0, response.Modified, user, response.Tally, response.Scores.data, response.Action, response.PageTitle, response.Ignored, response.ClamdResponses(), response.LogData)
		return
	case "block-invisible":
		showInvisibleBlock(w)
		logAccess(r, resp, 0, response.Modified, user, response.Tally, response.Scores.data, response.Action, response.PageTitle, response.Ignored, response.ClamdResponses(), response.LogData)
		return
	}

	if response.Response.ContentLength > 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(response.Response.ContentLength, 10))
	}
	copyResponseHeader(w, resp)
	n, err := io.Copy(w, response.Response.Body)
	if err != nil {
		if err != context.Canceled {
			log.Printf("error while copying response (URL: %s): %s", r.URL, err)
		}
		if ct, ok := rt.(*connTransport); ok {
			ct.Conn.Close()
		}
	}

	logAccess(r, resp, n, response.Modified, user, response.Tally, response.Scores.data, response.Action, response.PageTitle, response.Ignored, response.ClamdResponses(), response.LogData)
}

func filterRequest(req *Request, checkAuth bool) {
	r := req.Request

	req.Tally = getConfig().URLRules.MatchingRules(r.URL)
	req.Scores.data = getConfig().categoryScores(req.Tally)

	for _, classifier := range getConfig().ExternalClassifiers {
		v := make(url.Values)
		v.Set("url", r.URL.String())
		v.Set("method", r.Method)
		cr, err := clientWithExtraRootCerts.PostForm(classifier, v)
		if err != nil {
			log.Printf("Error checking external-classifier (%s): %v", classifier, err)
			continue
		}
		if cr.StatusCode != 200 {
			log.Printf("Bad HTTP status checking external-classifier (%s): %s", classifier, cr.Status)
			continue
		}
		jd := json.NewDecoder(cr.Body)
		externalScores := make(map[string]int)
		err = jd.Decode(&externalScores)
		cr.Body.Close()
		if err != nil {
			log.Printf("Error decoding response from external-classifier (%s): %v", classifier, err)
			continue
		}
		if req.Scores.data == nil {
			req.Scores.data = make(map[string]int)
		}
		for k, v := range externalScores {
			req.Scores.data[k] += v
		}
	}

	req.ACLs.data = getConfig().ACLs.requestACLs(r, req.User)
	req.PossibleActions = []string{
		"allow",
		"block",
		"block-invisible",
	}
	if req.User == "" && checkAuth {
		req.PossibleActions = append(req.PossibleActions, "require-auth")
	}

	callStarlarkFunctions("filter_request", req)
	req.chooseAction()
}

func doPhraseScan(response *Response) error {
	content, err := response.Content(getConfig().MaxContentScanSize)
	if err != nil {
		return err
	}
	if content != nil {
		conf := getConfig()
		contentType := response.Response.Header.Get("Content-Type")
		_, cs, _ := charset.DetermineEncoding(content, contentType)
		modified := false
		if strings.Contains(contentType, "html") {
			if conf.LogTitle {
				response.ParsedHTML, err = parseHTML(content, cs)
				if err != nil {
					log.Printf("Error parsing HTML from %s: %s", response.Request.Request.URL, err)
				} else {
					t := titleSelector.MatchFirst(response.ParsedHTML)
					if t != nil {
						if titleText := t.FirstChild; titleText != nil && titleText.Type == html.TextNode {
							response.PageTitle = strings.Replace(strings.TrimSpace(titleText.Data), "\n", " ", -1)
						}
					}
				}
			}

			modified = conf.pruneContent(response.Request.Request.URL, &content, cs, &response.ParsedHTML)
			if modified {
				cs = "utf-8"
			}
		}

		conf.scanContent(content, contentType, cs, response.Tally)

		if strings.Contains(contentType, "html") {
			aclsWithCategories := copyACLSet(response.ACLs.data)
			for name, score := range response.Scores.data {
				if category, ok := conf.Categories[name]; ok && category.action == ACL && score > 0 {
					aclsWithCategories[name] = true
				}
			}
			modifiedAfterScan := conf.doFilteredPruning(response.Request.Request.URL, content, cs, aclsWithCategories, &response.ParsedHTML)

			censorRule, _ := conf.ChooseACLCategoryAction(response.ACLs.data, response.Scores.data, conf.Threshold, "censor-words")
			if censorRule.Action == "censor-words" {
				if response.ParsedHTML == nil {
					response.ParsedHTML, _ = parseHTML(content, cs)
				}
				if censorHTML(response.ParsedHTML, conf.CensoredWords) {
					modifiedAfterScan = true
				}
			}

			if modifiedAfterScan {
				b := new(bytes.Buffer)
				if err := html.Render(b, response.ParsedHTML); err != nil {
					log.Printf("Error rendering modified content from %s: %v", response.Request.Request.URL, err)
				} else {
					content = b.Bytes()
					modified = true
				}
			}
			if modified {
				response.SetContent(content, "text/html; charset=utf-8")
			}
		}
	}
	return nil
}

func doImageHash(response *Response) error {
	content, err := response.Content(getConfig().MaxContentScanSize)
	if err != nil {
		return err
	}
	if content != nil {
		conf := getConfig()
		response.image, _, err = image.Decode(bytes.NewReader(content))
		if err != nil {
			log.Printf("Error decoding image from %v: %v", response.Request.Request.URL, err)
			return nil
		}
		hash := dhash.New(response.image)

		for _, h := range conf.ImageHashes {
			distance := dhash.Distance(hash, h.Hash)
			if distance <= h.Threshold || h.Threshold == -1 && distance <= conf.DhashThreshold {
				response.Tally[simpleRule{imageHash, h.String()}]++
			}
		}
	}
	return nil
}

// Thumbnail returns a JPEG thumbnail of the image in the response body.
// It will be no more than maxSize pixels in width or height.
// If the response body isn't a supported image type, or if it is
// longer than MaxContentScanSize, Thumbnail returns nil.
func (resp *Response) Thumbnail(maxSize int) []byte {
	if resp.image == nil {
		content, err := resp.Content(getConfig().MaxContentScanSize)
		if err != nil {
			log.Printf("Error downloading image from %v to make thumbnail: %v", resp.Request.Request.URL, err)
		}
		if content == nil {
			return nil
		}
		resp.image, _, err = image.Decode(bytes.NewReader(content))
		if err != nil {
			log.Printf("Error decoding image from %v: %v", resp.Request.Request.URL, err)
			return nil
		}
	}

	img := resp.image
	sb := img.Bounds()
	size := sb.Dx()
	if dy := sb.Dy(); dy > size {
		size = dy
	}
	if size > maxSize {
		ratio := float64(maxSize) / float64(size)
		dst := image.NewRGBA(image.Rect(0, 0, int(ratio*float64(sb.Dx())), int(ratio*float64(sb.Dy()))))
		draw.BiLinear.Scale(dst, dst.Bounds(), img, sb, draw.Over, nil)
		img = dst
	}

	b := new(bytes.Buffer)
	err := jpeg.Encode(b, img, &jpeg.Options{Quality: 80})
	if err != nil {
		return nil
	}
	return b.Bytes()
}

func doVirusScan(response *Response) error {
	content, err := response.Content(getConfig().MaxContentScanSize)
	if err != nil {
		return err
	}
	clam := getConfig().ClamAV
	if content != nil {
		response.clamResponses, err = clam.ScanReader(response.Request.Request.Context(), bytes.NewReader(content))
		if err != nil {
			log.Printf("Error doing virus scan on %v: %v", response.Request.Request.URL, err)
		}
		for _, res := range response.clamResponses {
			if res.Status == "FOUND" {
				log.Printf("Detected virus in %v: %s", response.Request.Request.URL, res.Signature)
				response.Action = ACLActionRule{
					Action: "block",
					Needed: []string{"virus", res.Signature},
				}
			}
		}
	} else {
		// Although the response is too long for synchronous virus scanning, scan it anyway,
		// so that we can log the result.

		// Make the channel buffered, so that sending won't block.
		response.clamChan = make(chan []*clamd.Response, 1)
		pr, pw := io.Pipe()
		tr := io.TeeReader(response.Response.Body, pw)
		response.Response.Body = pr
		go func() {
			cr, _ := clam.ScanReader(response.Request.Request.Context(), tr)
			io.Copy(ioutil.Discard, tr)
			pw.Close()
			response.clamChan <- cr
		}()
	}
	return nil
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

	if resp.Close {
		newHeader.Add("Connection", "close")
	}

	statusCode := resp.StatusCode
	if statusCode < 100 || statusCode >= 600 {
		statusCode = http.StatusBadGateway
	}
	w.WriteHeader(statusCode)
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
		return nil, fmt.Errorf("connection (%T) doesn't support hijacking", w)
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

	var err error = nil
	var serverConn net.Conn
	if ct, ok := h.rt.(*connTransport); ok {
		serverConn = ct.Conn
	} else if h.TLS {
		serverConn, err = dialWithExtraRootCerts("tcp", addr)
	} else {
		serverConn, err = net.Dial("tcp", addr)
	}
	if err != nil {
		log.Printf("Error making websocket connection to %s: %v", addr, err)
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
		log.Printf("Error sending websocket request to %s: %v", addr, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("Couldn't hijack client connection for websocket to %s", addr)
		http.Error(w, "Couldn't create a websocket connection", http.StatusInternalServerError)
		return
	}
	conn, bufrw, err := hj.Hijack()
	if err != nil {
		log.Printf("Error hijacking client connection for websocket to %s: %v", addr, err)
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

// A swallowErrorsWriter wraps an io.Writer so that writes always "succeed".
type swallowErrorsWriter struct {
	w   io.Writer
	err error
}

func (s *swallowErrorsWriter) Write(p []byte) (n int, err error) {
	if s.err == nil {
		n, err = s.w.Write(p)
		if err != nil {
			s.err = err
		}
	}
	return len(p), nil
}

// A Request is the parameter for the Starlark filter_request function.
type Request struct {
	Request      *http.Request
	User         string
	ExpectedUser string
	ClientIP     string
	LocalPort    int
	Session      *TLSSession

	// LogData is extra data to be included in log lines.
	LogData starlark.Value

	scoresAndACLs

	frozen      bool
	misc        starlark.Dict
	hostChanged bool
}

func (r *Request) String() string {
	return fmt.Sprintf("Request(%q)", r.Request.URL.String())
}

func (r *Request) Type() string {
	return "Request"
}

func (r *Request) Freeze() {
	if !r.frozen {
		r.frozen = true
		r.ACLs.Freeze()
		r.Scores.Freeze()
		r.misc.Freeze()
		if r.LogData != nil {
			r.LogData.Freeze()
		}
	}
}

func (r *Request) Truth() starlark.Bool {
	return starlark.True
}

func (r *Request) Hash() (uint32, error) {
	return 0, errors.New("unhashable type: Request")
}

var requestAttrNames = []string{"url", "method", "host", "path", "user", "expected_user", "local_port", "query", "header", "client_ip", "acls", "scores", "action", "possible_actions", "session", "misc", "log_data", "authenticated_clients"}

func (r *Request) AttrNames() []string {
	return requestAttrNames
}

func (r *Request) Attr(name string) (starlark.Value, error) {
	switch name {
	case "url":
		return starlark.String(r.Request.URL.String()), nil
	case "method":
		return starlark.String(r.Request.Method), nil
	case "host":
		return starlark.String(r.Request.Host), nil
	case "path":
		return starlark.String(r.Request.URL.Path), nil
	case "user":
		return starlark.String(r.User), nil
	case "expected_user":
		return starlark.String(r.ExpectedUser), nil
	case "client_ip":
		return starlark.String(r.ClientIP), nil
	case "local_port":
		return starlark.MakeInt(r.LocalPort), nil
	case "acls":
		return &r.ACLs, nil
	case "scores":
		return &r.Scores, nil
	case "action":
		ar, _ := r.currentAction()
		return starlark.String(ar.Action), nil
	case "possible_actions":
		return stringTuple(r.PossibleActions), nil
	case "header":
		return &HeaderDict{data: r.Request.Header}, nil
	case "query":
		return &QueryDict{
			data:     r.Request.URL.Query(),
			rawQuery: &r.Request.URL.RawQuery,
		}, nil
	case "session":
		if r.Session == nil {
			return starlark.None, nil
		}
		return r.Session, nil
	case "misc":
		return &r.misc, nil
	case "log_data":
		if r.LogData == nil {
			return starlark.None, nil
		}
		return r.LogData, nil
	case "authenticated_clients":
		var clients starlark.Tuple
		authCacheLock.RLock()
		defer authCacheLock.RUnlock()
		for ip, user := range authCache[r.LocalPort] {
			if user == r.ExpectedUser {
				clients = append(clients, starlark.String(ip))
			}
		}
		return clients, nil
	case "body":
		content, err := io.ReadAll(r.Request.Body)
		if err != nil {
			return starlark.None, err
		}
		r.Request.Body = io.NopCloser(bytes.NewReader(content))
		return starlark.String(content), nil

	default:
		return nil, nil
	}
}

func (r *Request) SetField(name string, val starlark.Value) error {
	if r.frozen {
		return errors.New("can't set a field of a frozen object")
	}

	switch name {
	case "url":
		var u string
		if err := assignStarlarkString(&u, val); err != nil {
			return err
		}
		parsed, err := url.Parse(u)
		if err != nil {
			return err
		}
		if parsed.Host != r.Request.URL.Host {
			r.Request.Host = parsed.Host
			r.hostChanged = true
		}
		r.Request.URL = parsed
		return nil
	case "path":
		return assignStarlarkString(&r.Request.URL.Path, val)
	case "action":
		var newAction string
		if err := assignStarlarkString(&newAction, val); err != nil {
			return err
		}
		return r.setAction(newAction)
	case "log_data":
		r.LogData = val
		return nil
	case "body":
		var body string
		err := assignStarlarkString(&body, val)
		if err != nil {
			return err
		}
		r.Request.ContentLength = int64(len(body))
		r.Request.Body = io.NopCloser(strings.NewReader(body))
		return nil
	default:
		return starlark.NoSuchAttrError(fmt.Sprintf("can't assign to .%s field of Request", name))
	}
}

// A Response is the parameter for the Starlark filter_response function.
type Response struct {
	Request  *Request
	Response *http.Response

	// LogData is extra data to be included in log lines.
	LogData starlark.Value

	scoresAndACLs

	Modified bool

	// PageTitle is the content of the page's title tag.
	// It is filled in by doPhraseScan.
	PageTitle string

	ParsedHTML *html.Node

	clamResponses []*clamd.Response
	clamChan      chan []*clamd.Response

	image image.Image

	frozen bool
	misc   starlark.Dict
}

func (r *Response) String() string {
	return fmt.Sprintf("Response(%q)", r.Request.Request.URL.String())
}

func (r *Response) Type() string {
	return "Response"
}

func (r *Response) Freeze() {
	if !r.frozen {
		r.frozen = true
		r.Request.Freeze()
		r.ACLs.Freeze()
		r.Scores.Freeze()
		r.misc.Freeze()
		if r.LogData != nil {
			r.LogData.Freeze()
		}
	}
}

func (r *Response) Truth() starlark.Bool {
	return starlark.True
}

func (r *Response) Hash() (uint32, error) {
	return 0, errors.New("unhashable type: Response")
}

var responseAttrNames = []string{"request", "header", "acls", "scores", "status", "body", "thumbnail", "action", "possible_actions", "misc", "log_data", "html", "title"}

func (r *Response) AttrNames() []string {
	return responseAttrNames
}

func (r *Response) Attr(name string) (starlark.Value, error) {
	switch name {
	case "request":
		return r.Request, nil
	case "acls":
		return &r.ACLs, nil
	case "scores":
		return &r.Scores, nil
	case "status":
		return starlark.MakeInt(r.Response.StatusCode), nil
	case "body":
		content, err := r.Content(getConfig().MaxContentScanSize)
		if err != nil {
			return starlark.None, err
		}
		if content == nil {
			return starlark.None, nil
		}
		return starlark.String(content), nil
	case "title":
		return starlark.String(r.PageTitle), nil
	case "action":
		ar, _ := r.currentAction()
		return starlark.String(ar.Action), nil
	case "possible_actions":
		return stringTuple(r.PossibleActions), nil
	case "header":
		return &HeaderDict{data: r.Response.Header}, nil
	case "misc":
		return &r.misc, nil
	case "log_data":
		if r.LogData == nil {
			return starlark.None, nil
		}
		return r.LogData, nil
	case "html":
		if r.ParsedHTML == nil {
			contentType := r.Response.Header.Get("Content-Type")
			if strings.Contains(contentType, "html") {
				content, err := r.Content(getConfig().MaxContentScanSize)
				if err == nil {
					_, cs, _ := charset.DetermineEncoding(content, contentType)
					r.ParsedHTML, err = parseHTML(content, cs)
				}
			}
		}

		n := r.ParsedHTML
		for n != nil && n.Type != html.ElementNode {
			switch n.Type {
			case html.DocumentNode:
				n = n.FirstChild
			case html.DoctypeNode, html.CommentNode:
				n = n.NextSibling
			default:
				return starlark.None, nil
			}
		}
		if n == nil {
			return starlark.None, nil
		}

		root := soup.Root{n, n.Data, nil}
		sn := bsoup.NewSoupNode(&root)
		return sn, nil

	case "thumbnail":
		return starlark.NewBuiltin("thumbnail", responseGetThumbnail).BindReceiver(r), nil

	default:
		return nil, nil
	}
}

func (r *Response) SetField(name string, val starlark.Value) error {
	if r.frozen {
		return errors.New("can't set a field of a frozen object")
	}

	switch name {
	case "status":
		status, err := starlark.NumberToInt(val)
		if err != nil {
			return err
		}
		status64, ok := status.Int64()
		if !ok || status64 >= 600 || status64 < 100 {
			return fmt.Errorf("invalid HTTP status code: %v", val)
		}
		r.Response.StatusCode = int(status64)
		return nil
	case "body":
		var body string
		err := assignStarlarkString(&body, val)
		if err != nil {
			return err
		}
		r.SetContent([]byte(body), r.Response.Header.Get("Content-Type"))
		return nil
	case "action":
		var newAction string
		if err := assignStarlarkString(&newAction, val); err != nil {
			return err
		}
		return r.setAction(newAction)
	case "log_data":
		r.LogData = val
		return nil
	case "title":
		return assignStarlarkString(&r.PageTitle, val)
	default:
		return starlark.NoSuchAttrError(fmt.Sprintf("can't assign to .%s field of Response", name))
	}
}

// Content reads the response body and returns it as a byte slice.
// If the Content-Encoding header indicates that the body is compressed,
// it will be decompressed.
// If the length of the body is more than maxLen, or it is a response to a HEAD
// request, it will return nil, nil.
func (resp *Response) Content(maxLen int) ([]byte, error) {
	if resp.Response.ContentLength > int64(maxLen) || resp.Request.Request.Method == "HEAD" {
		return nil, nil
	}

	lr := &io.LimitedReader{
		R: resp.Response.Body,
		N: int64(maxLen),
	}
	content, err := ioutil.ReadAll(lr)

	// Servers that use broken chunked Transfer-Encoding can give us unexpected EOFs,
	// even if we got all the content.
	if err == io.ErrUnexpectedEOF && resp.Response.ContentLength == -1 {
		err = nil
	}
	if err != nil {
		return nil, err
	}

	if lr.N == 0 {
		// We read maxLen without reaching the end.
		resp.Response.Body = io.NopCloser(io.MultiReader(bytes.NewReader(content), resp.Response.Body))
		return nil, nil
	}

	if resp.Response.Header.Get("Content-Encoding") == "" {
		resp.Response.ContentLength = int64(len(content))
	}
	resp.Response.Body = io.NopCloser(bytes.NewReader(content))

	if ce := resp.Response.Header.Get("Content-Encoding"); ce != "" && len(content) > 0 {
		br := bytes.NewReader(content)
		var decompressor io.Reader
		switch ce {
		case "br":
			decompressor = brotli.NewReader(br)
		case "deflate":
			decompressor = flate.NewReader(br)
		case "gzip":
			decompressor, err = gzip.NewReader(br)
			if err != nil {
				log.Printf("Error creating gzip.Reader for %v: %v", resp.Request.Request.URL, err)
				// At this point, decompressor is io.Reader(*gzip.Reader(nil)),
				// but it needs to be just io.Reader(nil), or we won't catch that it's nil
				// later on.
				decompressor = nil
			}
		default:
			log.Printf("Unrecognized Content-Encoding (%q) at %v", ce, resp.Request.Request.URL)
		}
		if decompressor != nil {
			decompressed, err := ioutil.ReadAll(decompressor)
			if err != nil {
				log.Printf("Error decompressing response body from %v: %v", resp.Request.Request.URL, err)
			} else {
				return decompressed, nil
			}
		}
	}

	return content, nil
}

// SetContent replaces the request body with the provided content, and sets
// the Content-Type header.
func (resp *Response) SetContent(data []byte, contentType string) {
	resp.Response.Header.Set("Content-Type", contentType)
	resp.Response.Header.Del("Content-Encoding")
	resp.Modified = true

	if len(data) > 1000 {
		encoding := httputil.NegotiateContentEncoding(resp.Request.Request, []string{"br", "gzip"})
		buf := new(bytes.Buffer)
		var compressor io.WriteCloser
		var err error
		switch encoding {
		case "br":
			compressor = brotli.NewWriterOptions(buf, brotli.WriterOptions{Quality: getConfig().BrotliLevel})
		case "gzip":
			compressor, err = gzip.NewWriterLevel(buf, getConfig().GZIPLevel)
			if err != nil {
				log.Println("Error creating gzip compressor:", err)
				compressor = nil
			}
		}
		if compressor != nil {
			compressor.Write(data)
			if err := compressor.Close(); err == nil {
				resp.Response.Body = io.NopCloser(buf)
				resp.Response.Header.Set("Content-Encoding", encoding)
				resp.Response.ContentLength = -1
				return
			}
		}
	}

	resp.Response.ContentLength = int64(len(data))
	resp.Response.Body = io.NopCloser(bytes.NewReader(data))
}

// ClamdResponses returns the results from ClamAV scanning, or nil if the
// response was not scanned.
func (resp *Response) ClamdResponses() []*clamd.Response {
	if resp.clamResponses != nil {
		return resp.clamResponses
	}
	if resp.clamChan != nil {
		resp.clamResponses = <-resp.clamChan
		return resp.clamResponses
	}
	return nil
}

func responseGetThumbnail(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	s := fn.Receiver().(*Response)
	if s.frozen && s.image == nil {
		return nil, errors.New("can't get a thumbnail for a frozen Response unless the image is already loaded")
	}

	size := 1000
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 0, &size); err != nil {
		return nil, err
	}

	thumbnail := s.Thumbnail(size)
	if thumbnail == nil {
		return starlark.None, nil
	}

	return starlark.String(thumbnail), nil
}

// A HeaderDict wraps an http.Header to make it act like a Starlark dictionary.
type HeaderDict struct {
	frozen    bool
	itercount int
	data      http.Header
}

func (h *HeaderDict) String() string {
	b := new(strings.Builder)
	h.data.Write(b)
	return b.String()
}

func (h *HeaderDict) Type() string {
	return "HeaderDict"
}

func (h *HeaderDict) Freeze() {
	if !h.frozen {
		h.frozen = true
	}
}

func (h *HeaderDict) Truth() starlark.Bool {
	return starlark.Bool(len(h.data) > 0)
}

func (h *HeaderDict) Hash() (uint32, error) {
	return 0, errors.New("unhashable type: HeaderDict")
}

type headerDictIterator struct {
	ss       *HeaderDict
	elements []string
}

func (it *headerDictIterator) Next(p *starlark.Value) bool {
	if len(it.elements) > 0 {
		*p = starlark.String(it.elements[0])
		it.elements = it.elements[1:]
		return true
	}
	return false
}

func (it *headerDictIterator) Done() {
	if !it.ss.frozen {
		it.ss.itercount--
	}
}

func (h *HeaderDict) keys() []string {
	keys := make([]string, 0, len(h.data))
	for k := range h.data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (h *HeaderDict) Iterate() starlark.Iterator {
	if !h.frozen {
		h.itercount++
	}
	return &headerDictIterator{
		ss:       h,
		elements: h.keys(),
	}
}

func (h *HeaderDict) Len() int {
	return len(h.data)
}

func (h *HeaderDict) Get(k starlark.Value) (v starlark.Value, found bool, err error) {
	ks, ok := k.(starlark.String)
	if !ok {
		return nil, false, nil
	}

	vals := h.data.Values(string(ks))
	if len(vals) == 0 {
		return nil, false, nil
	}
	return starlark.String(vals[0]), true, nil
}

func (h *HeaderDict) SetKey(k, v starlark.Value) error {
	ks, ok := k.(starlark.String)
	if !ok {
		return fmt.Errorf("keys for HeaderDict must be String, not %s", k.Type())
	}
	vs, ok := v.(starlark.String)
	if !ok {
		return fmt.Errorf("values for HeaderDict must be String, not %s", v.Type())
	}
	h.data.Set(string(ks), string(vs))
	return nil
}

var headerDictAttrNames = []string{"get", "pop"}

func (h *HeaderDict) AttrNames() []string {
	return headerDictAttrNames
}

func (h *HeaderDict) Attr(name string) (starlark.Value, error) {
	switch name {
	case "get", "pop":
		return starlark.NewBuiltin(name, headerDictGet).BindReceiver(h), nil
	default:
		return nil, nil
	}
}

func headerDictGet(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	pop := fn.Name() == "pop"

	s := fn.Receiver().(*HeaderDict)
	if pop {
		if s.frozen {
			return nil, errors.New("can't modify a frozen HeaderDict")
		}
		if s.itercount > 0 {
			return nil, errors.New("can't modify a HeaderDict during iteration")
		}
	}

	var key string
	var defaultValue starlark.Value
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 1, &key, &defaultValue); err != nil {
		return nil, err
	}
	if defaultValue == nil && !pop {
		defaultValue = starlark.None
	}

	vals := s.data.Values(key)
	if len(vals) == 0 {
		if defaultValue != nil {
			return defaultValue, nil
		}
		return nil, fmt.Errorf("key %q not in dict", key)
	}
	if pop {
		s.data.Del(key)
	}
	return starlark.String(vals[0]), nil
}

func (h *HeaderDict) Items() (result []starlark.Tuple) {
	for _, k := range h.keys() {
		result = append(result, starlark.Tuple{
			starlark.String(k),
			starlark.String(h.data.Get(k)),
		})
	}
	return result
}

// A QueryDict wraps url.Values to make it act like a Starlark dictionary.
type QueryDict struct {
	frozen    bool
	itercount int
	data      url.Values
	rawQuery  *string
}

func (h *QueryDict) String() string {
	return h.data.Encode()
}

func (h *QueryDict) Type() string {
	return "QueryDict"
}

func (h *QueryDict) Freeze() {
	if !h.frozen {
		h.frozen = true
	}
}

func (h *QueryDict) Truth() starlark.Bool {
	return starlark.Bool(len(h.data) > 0)
}

func (h *QueryDict) Hash() (uint32, error) {
	return 0, errors.New("unhashable type: QueryDict")
}

type queryDictIterator struct {
	ss       *QueryDict
	elements []string
}

func (it *queryDictIterator) Next(p *starlark.Value) bool {
	if len(it.elements) > 0 {
		*p = starlark.String(it.elements[0])
		it.elements = it.elements[1:]
		return true
	}
	return false
}

func (it *queryDictIterator) Done() {
	if !it.ss.frozen {
		it.ss.itercount--
	}
}

func (h *QueryDict) keys() []string {
	keys := make([]string, 0, len(h.data))
	for k := range h.data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (h *QueryDict) Iterate() starlark.Iterator {
	if !h.frozen {
		h.itercount++
	}
	return &queryDictIterator{
		ss:       h,
		elements: h.keys(),
	}
}

func (h *QueryDict) Len() int {
	return len(h.data)
}

func (h *QueryDict) Get(k starlark.Value) (v starlark.Value, found bool, err error) {
	ks, ok := k.(starlark.String)
	if !ok {
		return nil, false, nil
	}

	vals := h.data[string(ks)]
	if len(vals) == 0 {
		return nil, false, nil
	}
	return starlark.String(vals[0]), true, nil
}

func (h *QueryDict) SetKey(k, v starlark.Value) error {
	ks, ok := k.(starlark.String)
	if !ok {
		return fmt.Errorf("keys for QueryDict must be String, not %s", k.Type())
	}
	vs, ok := v.(starlark.String)
	if !ok {
		return fmt.Errorf("values for QueryDict must be String, not %s", v.Type())
	}
	h.data.Set(string(ks), string(vs))
	*h.rawQuery = h.data.Encode()
	return nil
}

var queryDictAttrNames = []string{"get", "pop"}

func (h *QueryDict) AttrNames() []string {
	return queryDictAttrNames
}

func (h *QueryDict) Attr(name string) (starlark.Value, error) {
	switch name {
	case "get", "pop":
		return starlark.NewBuiltin(name, queryDictGet).BindReceiver(h), nil
	default:
		return nil, nil
	}
}

func queryDictGet(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	pop := fn.Name() == "pop"

	s := fn.Receiver().(*QueryDict)
	if pop {
		if s.frozen {
			return nil, errors.New("can't modify a frozen QueryDict")
		}
		if s.itercount > 0 {
			return nil, errors.New("can't modify a QueryDict during iteration")
		}
	}

	var key string
	var defaultValue starlark.Value
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 1, &key, &defaultValue); err != nil {
		return nil, err
	}
	if defaultValue == nil && !pop {
		defaultValue = starlark.None
	}

	vals := s.data[key]
	if len(vals) == 0 {
		if defaultValue != nil {
			return defaultValue, nil
		}
		return nil, fmt.Errorf("key %q not in dict", key)
	}
	if pop {
		s.data.Del(key)
		*s.rawQuery = s.data.Encode()
	}
	return starlark.String(vals[0]), nil
}

func (h *QueryDict) Items() (result []starlark.Tuple) {
	for _, k := range h.keys() {
		result = append(result, starlark.Tuple{
			starlark.String(k),
			starlark.String(h.data.Get(k)),
		})
	}
	return result
}
