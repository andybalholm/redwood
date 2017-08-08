package main

import (
	"bytes"
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

	"golang.org/x/net/http2"
)

// Intercept TLS (HTTPS) connections.

// unverifiedClientConfig is a TLS configuration that doesn't verify server
// certificates.
var unverifiedClientConfig = &tls.Config{
	InsecureSkipVerify: true,
}

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
func connectDirect(conn net.Conn, serverAddr string, extraData []byte) (uploaded, downloaded int64) {
	activeConnections.Add(1)
	defer activeConnections.Done()

	serverConn, err := net.Dial("tcp", serverAddr)
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

	conf := getConfig()

	obsoleteVersion := false
	// Read the client hello so that we can find out the name of the server (not
	// just the address).
	clientHello, err := readClientHello(conn)
	if err != nil {
		logTLS(user, serverAddr, "", fmt.Errorf("error reading client hello: %v", err), false)
		if _, ok := err.(net.Error); ok {
			conn.Close()
			return
		} else if err == ErrObsoleteSSLVersion {
			obsoleteVersion = true
			if conf.BlockObsoleteSSL {
				conn.Close()
				return
			}
		} else {
			conn.Close()
			return
		}
	}

	serverName := ""
	if !obsoleteVersion {
		if sn, ok := clientHelloServerName(clientHello); ok {
			serverName = sn
			if serverAddr == "" {
				serverAddr = net.JoinHostPort(sn, "443")
			}
		}
	}

	if serverAddr == localServer+":443" {
		// The internal server gets special treatment, since there is no remote
		// server to connect to.
		cert, err := imitateCertificate(&x509.Certificate{
			Subject:     pkix.Name{CommonName: localServer},
			NotBefore:   conf.ParsedTLSCert.NotBefore,
			NotAfter:    conf.ParsedTLSCert.NotAfter,
			KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}, false, conf)
		if err != nil {
			log.Printf("Error generating HTTPS certificate for local server (%s): %v", serverAddr, err)
			conn.Close()
			return
		}

		config := &tls.Config{
			NextProtos:   []string{"http/1.1"},
			Certificates: []tls.Certificate{cert, conf.TLSCert},
		}
		tlsConn := tls.Server(conn, config)
		err = tlsConn.Handshake()
		if err != nil {
			logTLS(user, serverAddr, localServer, fmt.Errorf("error in handshake with client: %v", err), false)
			conn.Close()
			return
		}
		listener := &singleListener{conn: tlsConn}
		server := http.Server{
			Handler:     conf.ServeMux,
			IdleTimeout: conf.CloseIdleConnections,
		}
		conf = nil
		logTLS(user, serverAddr, localServer, nil, false)
		server.Serve(listener)
		return
	}

	host, port, err := net.SplitHostPort(serverAddr)
	if err != nil {
		host = serverAddr
		port = "443"
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

	// Filter a virtual CONNECT request.
	cr := &http.Request{
		Method:     "CONNECT",
		Header:     make(http.Header),
		Host:       net.JoinHostPort(serverName, port),
		URL:        &url.URL{Host: serverName},
		RemoteAddr: conn.RemoteAddr().String(),
	}

	tally := conf.URLRules.MatchingRules(cr.URL)
	scores := conf.categoryScores(tally)
	reqACLs := conf.ACLs.requestACLs(cr, authUser)

	possibleActions := []string{
		"allow",
		"block",
	}
	if conf.TLSReady && !obsoleteVersion {
		possibleActions = append(possibleActions, "ssl-bump")
	}

	rule, ignored := conf.ChooseACLCategoryAction(reqACLs, scores, conf.Threshold, possibleActions...)
	if r == nil {
		logAccess(cr, nil, 0, false, user, tally, scores, rule, "", ignored)
	} else {
		logAccess(r, nil, 0, false, user, tally, scores, rule, "", ignored)
	}

	switch rule.Action {
	case "allow", "":
		conf = nil
		upload, download := connectDirect(conn, serverAddr, clientHello)
		logAccess(cr, nil, int(upload+download), false, user, tally, scores, rule, "", ignored)
		return
	case "block":
		conn.Close()
		return
	}

	cert, rt := conf.CertCache.Get(serverName, serverAddr)
	cachedCert := rt != nil
	if !cachedCert {
		serverConn, err := tls.Dial("tcp", serverAddr, &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2", "http/1.1"},
		})
		if err != nil {
			logTLS(user, serverAddr, serverName, err, cachedCert)
			conf = nil
			connectDirect(conn, serverAddr, clientHello)
			return
		}

		state := serverConn.ConnectionState()
		serverConn.Close()
		serverCert := state.PeerCertificates[0]

		valid := conf.validCert(serverCert, state.PeerCertificates[1:])
		cert, err = imitateCertificate(serverCert, !valid, conf)
		if err != nil {
			serverConn.Close()
			logTLS(user, serverAddr, serverName, fmt.Errorf("error generating certificate: %v", err), cachedCert)
			conf = nil
			connectDirect(conn, serverAddr, clientHello)
			return
		}

		_, err = serverCert.Verify(x509.VerifyOptions{
			Intermediates: certPoolWith(state.PeerCertificates[1:]),
			DNSName:       serverName,
		})
		validWithDefaultRoots := err == nil

		if conf.HTTP2Upstream && state.NegotiatedProtocol == "h2" && state.NegotiatedProtocolIsMutual {
			if validWithDefaultRoots {
				rt = http2Transport
			} else {
				rt = newHardValidationTransport(insecureHTTP2Transport, serverName, state.PeerCertificates)
			}
		} else {
			if validWithDefaultRoots {
				rt = httpTransport
			} else {
				rt = newHardValidationTransport(insecureHTTPTransport, serverName, state.PeerCertificates)
			}
		}
		conf.CertCache.Put(serverName, serverAddr, cert, rt)
	}

	server := http.Server{
		Handler: proxyHandler{
			TLS:         true,
			connectPort: port,
			user:        authUser,
			rt:          rt,
		},
		TLSConfig: &tls.Config{
			Certificates:             []tls.Certificate{cert, conf.TLSCert},
			PreferServerCipherSuites: true,
			CurvePreferences: []tls.CurveID{
				tls.CurveP256,
				tls.X25519, // Go 1.8 only
			},
		},
		IdleTimeout: conf.CloseIdleConnections,
	}

	if conf.HTTP2Downstream {
		server.TLSConfig.NextProtos = []string{"h2", "http/1.1"}
		err = http2.ConfigureServer(&server, nil)
		if err != nil {
			log.Println("Error configuring HTTP/2 server:", err)
		}
	}

	tlsConn := tls.Server(&insertingConn{conn, clientHello}, server.TLSConfig)
	err = tlsConn.Handshake()
	if err != nil {
		logTLS(user, serverAddr, serverName, fmt.Errorf("error in handshake with client: %v", err), cachedCert)
		conn.Close()
		return
	}

	listener := &singleListener{conn: tlsConn}
	logTLS(user, serverAddr, serverName, nil, cachedCert)
	conf = nil
	server.Serve(listener)
}

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
func imitateCertificate(serverCert *x509.Certificate, selfSigned bool, conf *config) (cert tls.Certificate, err error) {
	// Use a hash of the real certificate as the serial number.
	h := md5.New()
	h.Write(serverCert.Raw)
	h.Write([]byte{2})

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

func (conf *config) validCert(cert *x509.Certificate, intermediates []*x509.Certificate) bool {
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
		return hello, fmt.Errorf("expected content type of 22, got %d", header[0])
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

func clientHelloServerName(data []byte) (name string, ok bool) {
	if len(data) < 5 {
		return "", false
	}
	// Strip off the record header.
	data = data[5:]

	if len(data) < 42 {
		return "", false
	}

	sessionIdLen := int(data[38])
	if sessionIdLen > 32 || len(data) < 39+sessionIdLen {
		return "", false
	}
	data = data[39+sessionIdLen:]
	if len(data) < 2 {
		return "", false
	}

	cipherSuiteLen := int(data[0])<<8 | int(data[1])
	if cipherSuiteLen%2 == 1 || len(data) < 2+cipherSuiteLen {
		return "", false
	}
	data = data[2+cipherSuiteLen:]
	if len(data) < 1 {
		return "", false
	}

	compressionMethodsLen := int(data[0])
	if len(data) < 1+compressionMethodsLen {
		return "", false
	}
	data = data[1+compressionMethodsLen:]
	if len(data) < 2 {
		return "", false
	}

	extensionsLength := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if extensionsLength != len(data) {
		return "", false
	}

	for len(data) != 0 {
		if len(data) < 4 {
			return "", false
		}
		extension := uint16(data[0])<<8 | uint16(data[1])
		length := int(data[2])<<8 | int(data[3])
		data = data[4:]
		if len(data) < length {
			return "", false
		}

		if extension == 0 /* server name */ {
			if length < 2 {
				return "", false
			}
			numNames := int(data[0])<<8 | int(data[1])
			d := data[2:]
			for i := 0; i < numNames; i++ {
				if len(d) < 3 {
					return "", false
				}
				nameType := d[0]
				nameLen := int(d[1])<<8 | int(d[2])
				d = d[3:]
				if len(d) < nameLen {
					return "", false
				}
				if nameType == 0 {
					return string(d[:nameLen]), true
				}
				d = d[nameLen:]
			}
		}

		data = data[length:]
	}

	return "", true
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

type CertificateCache struct {
	lock        sync.RWMutex
	cache       map[certCacheKey]certCacheEntry
	TTL         time.Duration
	lastCleaned time.Time
}

type certCacheKey struct {
	name, addr string
}

type certCacheEntry struct {
	certificate tls.Certificate
	transport   http.RoundTripper
	added       time.Time
}

func (c *CertificateCache) Put(serverName, serverAddr string, cert tls.Certificate, transport http.RoundTripper) {
	c.lock.Lock()
	defer c.lock.Unlock()

	now := time.Now()
	if c.cache == nil {
		c.cache = make(map[certCacheKey]certCacheEntry)
		c.lastCleaned = now
	}

	if now.Sub(c.lastCleaned) > c.TTL {
		// Remove expired entries.
		for k, v := range c.cache {
			if now.Sub(v.added) > c.TTL {
				delete(c.cache, k)
			}
		}
	}

	c.cache[certCacheKey{
		name: serverName,
		addr: serverAddr,
	}] = certCacheEntry{
		certificate: cert,
		transport:   transport,
		added:       now,
	}
}

func (c *CertificateCache) Get(serverName, serverAddr string) (tls.Certificate, http.RoundTripper) {
	c.lock.RLock()
	defer c.lock.RUnlock()

	v, ok := c.cache[certCacheKey{
		name: serverName,
		addr: serverAddr,
	}]

	if !ok || time.Now().Sub(v.added) > c.TTL {
		return tls.Certificate{}, nil
	}

	return v.certificate, v.transport
}
