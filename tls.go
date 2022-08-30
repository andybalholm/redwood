package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/open-ch/ja3"
	"go.starlark.net/starlark"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/net/http2"
)

// Intercept TLS (HTTPS) connections.

// loadCertificate loads the TLS certificate specified by certFile and keyFile
// into tlsCert.
func (c *config) loadCertificate() {
	if c.CertFile != "" && c.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
		if err != nil {
			log.Println("Error loading TLS certificate:", err)
			return
		}
		c.TLSCert = cert
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			log.Println("Error parsing X509 certificate:", err)
			return
		}
		c.ParsedTLSCert = parsed
		c.TLSReady = true

		c.ServeMux.HandleFunc("/cert.der", func(w http.ResponseWriter, r *http.Request) {
			tlsCert := c.TLSCert
			w.Header().Set("Content-Type", "application/x-x509-ca-cert")
			w.Write(tlsCert.Certificate[len(tlsCert.Certificate)-1])
		})
	}
}

// connectDirect connects to serverAddr and copies data between it and conn.
// extraData is sent to the server first.
func connectDirect(conn net.Conn, serverAddr string, extraData []byte, dialer *net.Dialer) (uploaded, downloaded int64) {
	activeConnections.Add(1)
	defer activeConnections.Done()

	serverConn, err := dialer.Dial("tcp", serverAddr)
	if err != nil {
		log.Printf("error with pass-through of SSL connection to %s: %s", serverAddr, err)
		conn.Close()
		return
	}

	if extraData != nil {
		// There may also be data waiting in the socket's input buffer;
		// read it before we send the data on, so that the first packet of
		// the connection doesn't get split in two.
		conn.SetReadDeadline(time.Now().Add(time.Millisecond))
		buf := make([]byte, 2000)
		n, _ := conn.Read(buf)
		conn.SetReadDeadline(time.Time{})
		if n > 0 {
			extraData = append(extraData, buf[:n]...)
		}
		serverConn.Write(extraData)
	}

	ulChan := make(chan int64)
	go func() {
		n, _ := io.Copy(conn, serverConn)
		time.Sleep(time.Second)
		conn.Close()
		ulChan <- n + int64(len(extraData))
	}()
	downloaded, _ = io.Copy(serverConn, conn)
	serverConn.Close()
	uploaded = <-ulChan
	return uploaded, downloaded
}

type tlsFingerprintKey struct{}

// SSLBump performs a man-in-the-middle attack on conn, to filter the HTTPS
// traffic. serverAddr is the address (host:port) of the server the client was
// trying to connect to. user is the username to use for logging; authUser is
// the authenticated user, if any; r is the CONNECT request, if any.
func SSLBump(conn net.Conn, serverAddr, user, authUser string, r *http.Request) {
	defer func() {
		if err := recover(); err != nil {
			buf := make([]byte, 4096)
			buf = buf[:runtime.Stack(buf, false)]
			log.Printf("SSLBump: panic serving connection to %s: %v\n%s", serverAddr, err, buf)
			conn.Close()
		}
	}()

	session := &TLSSession{
		ServerAddr: serverAddr,
		User:       authUser,
	}
	if r != nil {
		session.ConnectHeader = r.Header
	}

	client := conn.RemoteAddr().String()
	if host, _, err := net.SplitHostPort(client); err == nil {
		session.ClientIP = host
	} else {
		session.ClientIP = client
	}

	obsoleteVersion := false
	invalidSSL := false
	// Read the client hello so that we can find out the name of the server (not
	// just the address).
	clientHello, err := readClientHello(conn)
	if err != nil {
		logTLS(user, serverAddr, "", fmt.Errorf("error reading client hello: %v", err), false, "")
		if _, ok := err.(net.Error); ok {
			conn.Close()
			return
		} else if err == ErrObsoleteSSLVersion {
			obsoleteVersion = true
			if getConfig().BlockObsoleteSSL {
				conn.Close()
				return
			}
		} else if err == ErrInvalidSSL {
			invalidSSL = true
		} else {
			conn.Close()
			return
		}
	}
	clientHelloInfo, err := parseClientHello(clientHello)

	host, port, err := net.SplitHostPort(serverAddr)
	if err != nil {
		host = serverAddr
		port = "443"
	}

	serverName := ""
	if !obsoleteVersion && !invalidSSL {
		if clientHelloInfo != nil && clientHelloInfo.ServerName != "" {
			serverName = clientHelloInfo.ServerName
		}
	}
	session.SNI = serverName
	if session.ServerAddr == "" {
		session.ServerAddr = net.JoinHostPort(serverName, "443")
	}

	if serverName == "" {
		serverName = host
		if ip := net.ParseIP(serverName); ip != nil {
			// All we have is an IP address, not a name from a CONNECT request.
			// See if we can do better by reverse DNS.
			names, err := net.LookupAddr(serverName)
			if err == nil && len(names) > 0 {
				serverName = strings.TrimSuffix(names[0], ".")
			}
		}
	}

	if serverName == "" {
		logTLS(user, "", "", errors.New("no SNI available"), false, "")
		conn.Close()
		return
	}

	// Filter a virtual CONNECT request.
	cr := &http.Request{
		Method:     "CONNECT",
		Header:     make(http.Header),
		Host:       net.JoinHostPort(serverName, port),
		URL:        &url.URL{Host: serverName},
		RemoteAddr: conn.RemoteAddr().String(),
	}

	var tlsFingerprint string
	j, err := ja3.ComputeJA3FromSegment(clientHello)
	if err != nil {
		log.Printf("Error generating TLS fingerprint: %v", err)
	} else {
		tlsFingerprint = j.GetJA3Hash()
		ctx := cr.Context()
		ctx = context.WithValue(ctx, tlsFingerprintKey{}, tlsFingerprint)
		cr = cr.WithContext(ctx)
	}

	var tally map[rule]int
	var scores map[string]int
	var reqACLs map[string]bool
	{
		conf := getConfig()
		tally = conf.URLRules.MatchingRules(cr.URL)
		scores = conf.categoryScores(tally)
		reqACLs = conf.ACLs.requestACLs(cr, authUser)
		if invalidSSL {
			reqACLs["invalid-ssl"] = true
		}
		if r == nil {
			// It's a transparently-intercepted request instead of a real
			// CONNECT request.
			reqACLs["transparent"] = true
		}
	}
	session.ACLs.data = reqACLs
	session.Scores.data = scores
	session.PossibleActions = []string{"allow", "block"}
	if getConfig().TLSReady && !obsoleteVersion && !invalidSSL {
		session.PossibleActions = append(session.PossibleActions, "ssl-bump")
	}

	callStarlarkFunctions("ssl_bump", session)

	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}
	if session.SourceIP != nil {
		dialer.LocalAddr = &net.TCPAddr{
			IP: session.SourceIP,
		}
	}

	session.chooseAction()

	logAccess(cr, nil, 0, false, user, tally, scores, session.Action, "", session.Ignored, nil)

	switch session.Action.Action {
	case "allow", "":
		upload, download := connectDirect(conn, session.ServerAddr, clientHello, dialer)
		logAccess(cr, nil, upload+download, false, user, tally, scores, session.Action, "", session.Ignored, nil)
		return
	case "block":
		conn.Close()
		return
	}

	var cert tls.Certificate
	var rt http.RoundTripper
	var http2Support bool

	closeChan := make(chan struct{})
	server := &http.Server{
		IdleTimeout: getConfig().CloseIdleConnections,
		ConnState: func(conn net.Conn, state http.ConnState) {
			switch state {
			case http.StateClosed:
				close(closeChan)
			}
		},
	}

	serverConnConfig := &tls.Config{
		ServerName:         session.SNI,
		InsecureSkipVerify: true,
	}
	clientSupportsHTTP2 := false
	if clientHelloInfo != nil {
		for _, p := range clientHelloInfo.SupportedProtos {
			if p == "h2" {
				clientSupportsHTTP2 = true
			}
		}
	}
	if clientSupportsHTTP2 && getConfig().HTTP2Upstream {
		serverConnConfig.NextProtos = []string{"h2", "http/1.1"}
	}

	serverConn, err := tls.DialWithDialer(dialer, "tcp", session.ServerAddr, serverConnConfig)
	if err == nil {
		defer serverConn.Close()
		state := serverConn.ConnectionState()
		serverCert := state.PeerCertificates[0]

		valid := validCert(serverCert, state.PeerCertificates[1:])
		cert, err = imitateCertificate(serverCert, !valid, session.SNI)
		if err != nil {
			logTLS(user, session.ServerAddr, serverName, fmt.Errorf("error generating certificate: %v", err), false, tlsFingerprint)
			connectDirect(conn, session.ServerAddr, clientHello, dialer)
			return
		}

		http2Support = state.NegotiatedProtocol == "h2" && state.NegotiatedProtocolIsMutual

		d := &tls.Dialer{
			NetDialer: dialer,
			Config: &tls.Config{
				ServerName: session.SNI,
				RootCAs:    certPoolWith(serverConn.ConnectionState().PeerCertificates),
			},
		}
		if !valid {
			d.Config.InsecureSkipVerify = true
			originalCert := serverConn.ConnectionState().PeerCertificates[0]
			d.Config.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				cert, err := x509.ParseCertificate(rawCerts[0])
				if err != nil {
					return err
				}
				if cert.Equal(originalCert) {
					return nil
				}
				return errCertMismatch
			}
		}

		if http2Support {
			d.Config.NextProtos = []string{"h2"}

			var once sync.Once
			rt = &http2.Transport{
				DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
					var c net.Conn
					once.Do(func() {
						c = serverConn
					})
					if c != nil {
						return c, nil
					}
					logVerbose("redial", "Redialing HTTP/2 connection to %s (%s)", session.SNI, session.ServerAddr)
					return d.Dial("tcp", session.ServerAddr)
				},
				TLSClientConfig:            d.Config,
				StrictMaxConcurrentStreams: true,
			}
		} else {
			rt = &connTransport{
				Conn: serverConn,
				Redial: func(ctx context.Context) (net.Conn, error) {
					logVerbose("redial", "Redialing connection to %s (%s)", session.SNI, session.ServerAddr)
					return d.DialContext(ctx, "tcp", session.ServerAddr)
				},
			}
		}
	} else {
		cert, err = fakeCertificate(session.SNI)
		if err != nil {
			logTLS(user, session.ServerAddr, serverName, fmt.Errorf("error generating certificate: %v", err), false, tlsFingerprint)
			conn.Close()
			return
		}
		rt = httpTransport
	}

	session.Freeze()
	server.Handler = &proxyHandler{
		TLS:            true,
		tlsFingerprint: tlsFingerprint,
		connectPort:    port,
		user:           authUser,
		rt:             rt,
		session:        session,
	}
	tlsConfig := &tls.Config{
		Certificates:             []tls.Certificate{cert, getConfig().TLSCert},
		PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519, // Go 1.8 only
		},
	}

	http2Downstream := getConfig().HTTP2Downstream && http2Support
	if http2Downstream {
		tlsConfig.NextProtos = []string{"h2", "http/1.1"}
	}

	tlsConn := tls.Server(&insertingConn{conn, clientHello}, tlsConfig)
	err = tlsConn.Handshake()
	if err != nil {
		logTLS(user, session.ServerAddr, serverName, fmt.Errorf("error in handshake with client: %v", err), false, tlsFingerprint)
		conn.Close()
		return
	}

	logTLS(user, session.ServerAddr, serverName, nil, false, tlsFingerprint)

	if http2Downstream {
		http2.ConfigureServer(server, nil)
	}
	listener := &singleListener{conn: tlsConn}
	server.Serve(listener)

	// Wait for the connection to finish.
	<-closeChan
}

// A TLSSession is the parameter for the Starlark ssl_bump function.
type TLSSession struct {
	SNI        string
	ServerAddr string
	User       string
	ClientIP   string

	// SourceIP is the IP address of the network interface to be used fo dial
	// the upstream connection.
	SourceIP net.IP

	// ConnectHeader is the header from the CONNECT request, if any.
	ConnectHeader http.Header

	scoresAndACLs

	frozen bool
	misc   SyncDict
}

type scoresAndACLs struct {
	ACLs   StringSet
	Scores StringIntDict
	Tally  map[rule]int

	PossibleActions []string
	Action          ACLActionRule
	Ignored         []string
}

func (s *scoresAndACLs) currentAction() (ar ACLActionRule, ignored []string) {
	if s.Action.Action != "" {
		return s.Action, s.Ignored
	}
	conf := getConfig()
	ar, ignored = conf.ChooseACLCategoryAction(s.ACLs.data, s.Scores.data, conf.Threshold, s.PossibleActions...)
	if ar.Action == "" {
		ar.Action = "allow"
	}
	return ar, ignored
}

func (s *scoresAndACLs) chooseAction() {
	s.Action, s.Ignored = s.currentAction()
}

func (s *scoresAndACLs) setAction(newAction string) error {
	for _, a := range s.PossibleActions {
		if newAction == a {
			s.Action = ACLActionRule{
				Action: newAction,
				Needed: []string{"starlark"},
			}
			return nil
		}
	}
	return fmt.Errorf("can't set action to %q; expected one of %q", newAction, s.PossibleActions)
}

func (s *TLSSession) String() string {
	return fmt.Sprintf("TLSSession(%q, %q)", s.SNI, s.ServerAddr)
}

func (s *TLSSession) Type() string {
	return "TLSSession"
}

func (s *TLSSession) Freeze() {
	if !s.frozen {
		s.frozen = true
		s.ACLs.Freeze()
		s.Scores.Freeze()
	}
}

func (s *TLSSession) Truth() starlark.Bool {
	return starlark.True
}

func (s *TLSSession) Hash() (uint32, error) {
	return 0, errors.New("unhashable type: TLSSession")
}

var tlsSessionAttrNames = []string{"sni", "server_addr", "user", "client_ip", "acls", "scores", "source_ip", "action", "possible_actions", "header", "misc"}

func (s *TLSSession) AttrNames() []string {
	return tlsSessionAttrNames
}

func (s *TLSSession) Attr(name string) (starlark.Value, error) {
	switch name {
	case "sni":
		return starlark.String(s.SNI), nil
	case "server_addr":
		return starlark.String(s.ServerAddr), nil
	case "user":
		return starlark.String(s.User), nil
	case "client_ip":
		return starlark.String(s.ClientIP), nil
	case "source_ip":
		return starlark.String(s.SourceIP.String()), nil
	case "acls":
		return &s.ACLs, nil
	case "scores":
		return &s.Scores, nil
	case "action":
		ar, _ := s.currentAction()
		return starlark.String(ar.Action), nil
	case "possible_actions":
		return stringTuple(s.PossibleActions), nil
	case "header":
		return &HeaderDict{data: s.ConnectHeader}, nil
	case "misc":
		return &s.misc, nil

	default:
		return nil, nil
	}
}

func (s *TLSSession) SetField(name string, val starlark.Value) error {
	if s.frozen {
		return errors.New("can't set a field of a frozen object")
	}

	switch name {
	case "sni":
		return assignStarlarkString(&s.SNI, val)
	case "server_addr":
		return assignStarlarkString(&s.ServerAddr, val)
	case "source_ip":
		var ip string
		if err := assignStarlarkString(&ip, val); err != nil {
			return err
		}
		parsed := net.ParseIP(ip)
		if parsed == nil {
			return fmt.Errorf("%q is not a valid IP address", ip)
		}
		s.SourceIP = parsed
		return nil
	case "action":
		var newAction string
		if err := assignStarlarkString(&newAction, val); err != nil {
			return err
		}
		return s.setAction(newAction)
	default:
		return starlark.NoSuchAttrError(fmt.Sprintf("can't assign to .%s field of TLSSession", name))
	}
}

var errCertMismatch = errors.New("server certificate changed between original connection and redial")

func certPoolWith(certs []*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool
}

// A insertingConn is a net.Conn that inserts extra data at the start of the
// incoming data stream.
type insertingConn struct {
	net.Conn
	extraData []byte
}

func (c *insertingConn) Read(p []byte) (n int, err error) {
	if len(c.extraData) == 0 {
		return c.Conn.Read(p)
	}

	n = copy(p, c.extraData)
	c.extraData = c.extraData[n:]
	return
}

// A singleListener is a net.Listener that returns a single connection, then
// gives the error io.EOF.
type singleListener struct {
	conn net.Conn
	once sync.Once
}

func (s *singleListener) Accept() (net.Conn, error) {
	var c net.Conn
	s.once.Do(func() {
		c = s.conn
	})
	if c != nil {
		return c, nil
	}
	return nil, io.EOF
}

func (s *singleListener) Close() error {
	s.once.Do(func() {
		s.conn.Close()
	})
	return nil
}

func (s *singleListener) Addr() net.Addr {
	return s.conn.LocalAddr()
}

// imitateCertificate returns a new TLS certificate that has most of the same
// data as serverCert but is signed by Redwood's root certificate, or
// self-signed.
func imitateCertificate(serverCert *x509.Certificate, selfSigned bool, sni string) (cert tls.Certificate, err error) {
	conf := getConfig()
	// Use a hash of the real certificate (plus some other things) as the serial number.
	h := md5.New()
	h.Write(serverCert.Raw)
	for _, c := range conf.TLSCert.Certificate {
		h.Write(c)
	}
	if sni != "" {
		io.WriteString(h, sni)
	}

	template := &x509.Certificate{
		SerialNumber:                big.NewInt(0).SetBytes(h.Sum(nil)),
		Subject:                     serverCert.Subject,
		NotBefore:                   serverCert.NotBefore,
		NotAfter:                    serverCert.NotAfter,
		KeyUsage:                    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:                 serverCert.ExtKeyUsage,
		UnknownExtKeyUsage:          serverCert.UnknownExtKeyUsage,
		BasicConstraintsValid:       false,
		SubjectKeyId:                nil,
		DNSNames:                    serverCert.DNSNames,
		PermittedDNSDomainsCritical: serverCert.PermittedDNSDomainsCritical,
		PermittedDNSDomains:         serverCert.PermittedDNSDomains,
		SignatureAlgorithm:          x509.UnknownSignatureAlgorithm,
	}

	// If sni is not blank, make a certificate that covers only that domain,
	// instead of all the domains covered by the original certificate.
	if sni != "" {
		template.DNSNames = []string{sni}
		template.Subject.CommonName = sni
	}

	var newCertBytes []byte
	if selfSigned {
		newCertBytes, err = x509.CreateCertificate(rand.Reader, template, template, conf.ParsedTLSCert.PublicKey, conf.TLSCert.PrivateKey)
	} else {
		newCertBytes, err = x509.CreateCertificate(rand.Reader, template, conf.ParsedTLSCert, conf.ParsedTLSCert.PublicKey, conf.TLSCert.PrivateKey)
	}
	if err != nil {
		return tls.Certificate{}, err
	}

	newCert := tls.Certificate{
		Certificate: [][]byte{newCertBytes},
		PrivateKey:  conf.TLSCert.PrivateKey,
	}

	if !selfSigned {
		newCert.Certificate = append(newCert.Certificate, conf.TLSCert.Certificate...)
	}
	return newCert, nil
}

// fakeCertificate returns a fabricated certificate for the server identified by sni.
func fakeCertificate(sni string) (cert tls.Certificate, err error) {
	conf := getConfig()
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return tls.Certificate{}, err
	}
	y, m, d := time.Now().Date()

	template := &x509.Certificate{
		SerialNumber:       serial,
		Subject:            pkix.Name{CommonName: sni},
		NotBefore:          time.Date(y, m, d, 0, 0, 0, 0, time.Local),
		NotAfter:           time.Date(y, m+1, d, 0, 0, 0, 0, time.Local),
		KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		DNSNames:           []string{sni},
		SignatureAlgorithm: x509.UnknownSignatureAlgorithm,
	}

	newCertBytes, err := x509.CreateCertificate(rand.Reader, template, conf.ParsedTLSCert, conf.ParsedTLSCert.PublicKey, conf.TLSCert.PrivateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	newCert := tls.Certificate{
		Certificate: [][]byte{newCertBytes},
		PrivateKey:  conf.TLSCert.PrivateKey,
	}

	newCert.Certificate = append(newCert.Certificate, conf.TLSCert.Certificate...)
	return newCert, nil
}

func validCert(cert *x509.Certificate, intermediates []*x509.Certificate) bool {
	conf := getConfig()
	pool := certPoolWith(intermediates)
	_, err := cert.Verify(x509.VerifyOptions{Intermediates: pool})
	if err == nil {
		return true
	}
	if _, ok := err.(x509.UnknownAuthorityError); !ok {
		// There was an error, but not because the certificate wasn't signed
		// by a recognized CA. So we go ahead and use the cert and let
		// the client experience the same error.
		return true
	}

	if conf.ExtraRootCerts != nil {
		_, err = cert.Verify(x509.VerifyOptions{Roots: conf.ExtraRootCerts, Intermediates: pool})
		if err == nil {
			return true
		}
		if _, ok := err.(x509.UnknownAuthorityError); !ok {
			return true
		}
	}

	// Before we give up, we'll try fetching some intermediate certificates.
	if len(cert.IssuingCertificateURL) == 0 {
		return false
	}

	toFetch := cert.IssuingCertificateURL
	fetched := make(map[string]bool)

	for i := 0; i < len(toFetch); i++ {
		certURL := toFetch[i]
		if fetched[certURL] {
			continue
		}
		resp, err := http.Get(certURL)
		if err == nil {
			defer resp.Body.Close()
		}
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		fetchedCert, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		// The fetched certificate might be in either DER or PEM format.
		if bytes.Contains(fetchedCert, []byte("-----BEGIN CERTIFICATE-----")) {
			// It's PEM.
			var certDER *pem.Block
			for {
				certDER, fetchedCert = pem.Decode(fetchedCert)
				if certDER == nil {
					break
				}
				if certDER.Type != "CERTIFICATE" {
					continue
				}
				thisCert, err := x509.ParseCertificate(certDER.Bytes)
				if err != nil {
					continue
				}
				pool.AddCert(thisCert)
				toFetch = append(toFetch, thisCert.IssuingCertificateURL...)
			}
		} else {
			// Hopefully it's DER.
			thisCert, err := x509.ParseCertificate(fetchedCert)
			if err != nil {
				continue
			}
			pool.AddCert(thisCert)
			toFetch = append(toFetch, thisCert.IssuingCertificateURL...)
		}
	}

	_, err = cert.Verify(x509.VerifyOptions{Intermediates: pool})
	if err == nil {
		return true
	}
	if _, ok := err.(x509.UnknownAuthorityError); !ok {
		// There was an error, but not because the certificate wasn't signed
		// by a recognized CA. So we go ahead and use the cert and let
		// the client experience the same error.
		return true
	}
	return false
}

var ErrObsoleteSSLVersion = errors.New("obsolete SSL protocol version")
var ErrInvalidSSL = errors.New("invalid first byte for SSL connection; possibly some other protocol")

func readClientHello(conn net.Conn) (hello []byte, err error) {
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	var header [5]byte
	n, err := io.ReadFull(conn, header[:])
	hello = header[:n]
	if err != nil {
		return hello, err
	}

	if header[0] != 22 {
		if header[0] == 128 {
			return hello, ErrObsoleteSSLVersion
		}
		return hello, ErrInvalidSSL
	}
	if header[1] != 3 {
		return hello, fmt.Errorf("expected major version of 3, got %d", header[1])
	}
	recordLen := int(header[3])<<8 | int(header[4])
	if recordLen > 0x3000 {
		return hello, fmt.Errorf("expected length less than 12kB, got %d", recordLen)
	}
	if recordLen < 4 {
		return hello, fmt.Errorf("expected length of at least 4 bytes, got %d", recordLen)
	}

	protocolData := make([]byte, recordLen)
	n, err = io.ReadFull(conn, protocolData)
	hello = append(hello, protocolData[:n]...)
	if err != nil {
		return hello, err
	}
	if protocolData[0] != 1 {
		return hello, fmt.Errorf("Expected message type 1 (ClientHello), got %d", protocolData[0])
	}
	protocolLen := int(protocolData[1])<<16 | int(protocolData[2])<<8 | int(protocolData[3])
	if protocolLen != recordLen-4 {
		return hello, fmt.Errorf("recordLen=%d, protocolLen=%d", recordLen, protocolLen)
	}

	return hello, nil
}

// parseClientHello parses some useful information out of a ClientHello message.
// It returns a ClientHelloInfo with only the following fields filled in:
// ServerName and SupportedProtocols.
func parseClientHello(data []byte) (*tls.ClientHelloInfo, error) {
	// The implementation of this function is based on crypto/tls.clientHelloMsg.unmarshal
	var info tls.ClientHelloInfo
	s := cryptobyte.String(data)

	// Skip message type, length, version, and random.
	if !s.Skip(43) {
		return nil, errors.New("too short")
	}

	var sessionID cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&sessionID) {
		return nil, errors.New("bad session ID")
	}

	var cipherSuites cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cipherSuites) {
		return nil, errors.New("bad cipher suites")
	}

	var compressionMethods cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&compressionMethods) {
		return nil, errors.New("bad compression methods")
	}

	if s.Empty() {
		// no extensions
		return &info, nil
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return nil, errors.New("bad extensions")
	}

	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) || !extensions.ReadUint16LengthPrefixed(&extData) {
			return nil, errors.New("bad extension")
		}

		switch extension {
		case 0: // server name
			var nameList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&nameList) || nameList.Empty() {
				return nil, errors.New("bad name list")
			}
			for !nameList.Empty() {
				var nameType uint8
				var serverName cryptobyte.String
				if !nameList.ReadUint8(&nameType) || !nameList.ReadUint16LengthPrefixed(&serverName) || serverName.Empty() {
					return nil, errors.New("bad entry in name list")
				}
				if nameType != 0 {
					continue
				}
				if info.ServerName != "" {
					return nil, errors.New("multiple server names")
				}
				info.ServerName = string(serverName)
				if strings.HasSuffix(info.ServerName, ".") {
					return nil, errors.New("server name ends with dot")
				}
			}

		case 16: // ALPN
			var protoList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&protoList) || protoList.Empty() {
				return nil, errors.New("bad ALPN protocol list")
			}
			for !protoList.Empty() {
				var proto cryptobyte.String
				if !protoList.ReadUint8LengthPrefixed(&proto) || proto.Empty() {
					return nil, errors.New("bad ALPN protocol list entry")
				}
				info.SupportedProtos = append(info.SupportedProtos, string(proto))
			}

		default:
			// ignore
			continue
		}

		if !extData.Empty() {
			return nil, errors.New("extra data at end of extension")
		}
	}

	return &info, nil
}

func (c *config) addTrustedRoots(certPath string) error {
	if c.ExtraRootCerts == nil {
		c.ExtraRootCerts = x509.NewCertPool()
	}

	pem, err := ioutil.ReadFile(certPath)
	if err != nil {
		return err
	}

	if !c.ExtraRootCerts.AppendCertsFromPEM(pem) {
		return fmt.Errorf("no certificates found in %s", certPath)
	}
	return nil
}
