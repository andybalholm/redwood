package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
)

// Intercept TLS (HTTPS) connections.

var certFile = flag.String("tls-cert", "", "path to certificate for serving HTTPS")
var keyFile = flag.String("tls-key", "", "path to TLS certificate key")
var sslBypassFile = newActiveFlag("tls-bypass", "", "path to list of sites that bypass SSLBump", readBypassFile)
var tlsVerbose = flag.Bool("tls-verbose", false, "log all intercepted HTTPS connections")

var tlsCert tls.Certificate
var parsedTLSCert *x509.Certificate
var tlsReady bool

var tlsBypass = map[string]bool{}
var tlsBypassRanges []*net.IPNet
var tlsBypassDomains []string

// unverifiedClientConfig is a TLS configuration that doesn't verify server
// certificates.
var unverifiedClientConfig = &tls.Config{
	InsecureSkipVerify: true,
}

// loadCertificate loads the TLS certificate specified by certFile and keyFile
// into tlsCert.
func loadCertificate() {
	if *certFile != "" && *keyFile != "" {
		cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			log.Println("Error loading TLS certificate:", err)
			return
		}
		tlsCert = cert
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			log.Println("Error parsing X509 certificate:", err)
			return
		}
		parsedTLSCert = parsed
		tlsReady = true

		http.HandleFunc("/cert.der", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/x-x509-ca-cert")
			w.Write(tlsCert.Certificate[len(tlsCert.Certificate)-1])
		})

		go cacheCertificates()
	}
}

func shouldBypass(host string) bool {
	if tlsBypass[host] {
		return true
	}
	for _, domain := range tlsBypassDomains {
		if strings.HasSuffix(host, domain) {
			return true
		}
	}
	addr := net.ParseIP(host)
	if addr == nil {
		return false
	}
	for _, subnet := range tlsBypassRanges {
		if subnet.Contains(addr) {
			return true
		}
	}
	return false
}

// connectDirect connects to serverAddr and copies data between it and conn.
// extraData is sent to the server first.
func connectDirect(conn net.Conn, serverAddr string, extraData []byte) {
	activeConnections.Add(1)
	defer activeConnections.Done()

	if *tlsVerbose {
		log.Printf("connecting %s directly to %s", conn.RemoteAddr(), serverAddr)
	}
	serverConn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		log.Printf("error with pass-through of SSL connection to %s: %s", serverAddr, err)
		return
	}

	if extraData != nil {
		serverConn.Write(extraData)
	}

	go func() {
		io.Copy(conn, serverConn)
		conn.Close()
	}()
	io.Copy(serverConn, conn)
	serverConn.Close()
	return
}

// SSLBump performs a man-in-the-middle attack on conn, to filter the HTTPS
// traffic. serverAddr is the address (host:port) of the server the client was
// trying to connect to. user is the name of an already-authenticated user.
func SSLBump(conn net.Conn, serverAddr, user string) {
	defer func() {
		if err := recover(); err != nil {
			buf := make([]byte, 4096)
			buf = buf[:runtime.Stack(buf, false)]
			log.Printf("SSLBump: panic serving connection to %s: %v\n%s", serverAddr, err, buf)
			conn.Close()
		}
	}()

	// Read the client hello so that we can find out the name of the server (not
	// just the address).
	clientHello, err := readClientHello(conn)
	if err != nil {
		log.Printf("error reading client hello in TLS connection from %s to %s: %s", conn.RemoteAddr(), serverAddr, err)
		connectDirect(conn, serverAddr, clientHello)
		return
	}

	serverName, ok := clientHelloServerName(clientHello)
	if ok && serverName != "" {
		if *tlsVerbose {
			log.Printf("Server name requested for %s is %s.", serverAddr, serverName)
		}
		if shouldBypass(serverName) {
			connectDirect(conn, serverAddr, clientHello)
			return
		}
	} else {
		if *tlsVerbose {
			log.Printf("Could not find server name for %s.", serverAddr)
		}
		if host, _, err := net.SplitHostPort(serverAddr); err == nil && shouldBypass(host) {
			connectDirect(conn, serverAddr, clientHello)
			return
		}
	}

	if *tlsVerbose {
		log.Printf("intercepting TLS connection from %s to %s", conn.RemoteAddr(), serverAddr)
	}

	cert, err := getCertificate(serverAddr, serverName)
	if err != nil {
		// Since it doesn't seem to be an HTTPS server, just connect directly.
		log.Printf("Could not generate a TLS certificate for %s (%s); letting the client connect directly", serverAddr, err)
		connectDirect(conn, serverAddr, clientHello)
		return
	}

	config := &tls.Config{
		NextProtos:   []string{"http/1.1"},
		Certificates: []tls.Certificate{cert, tlsCert},
	}

	tlsConn := tls.Server(&insertingConn{conn, clientHello}, config)
	err = tlsConn.Handshake()
	if err != nil {
		log.Printf("Error in TLS handshake for SSLBump connection from %v to %v: %v", conn.RemoteAddr(), serverAddr, err)
		return
	}

	_, port, err := net.SplitHostPort(serverAddr)
	if err != nil {
		port = ""
	}
	listener := &singleListener{conn: tlsConn}
	server := http.Server{
		Handler: proxyHandler{
			TLS:         true,
			connectPort: port,
			user:        user,
		},
	}
	server.Serve(listener)
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

// maxSerial is the largest serial number to use for a certificate.
var maxSerial = big.NewInt(1<<63 - 1)

// generateCertificate connects to the server at addr, gets its TLS
// certificate, and returns a new certificate to be used when proxying
// connections to that server. It sends a TLS Server Name Indication
// with name.
func generateCertificate(addr, name string) (cert tls.Certificate, err error) {
	defer func() {
		if e := recover(); e != nil {
			buf := make([]byte, 4096)
			buf = buf[:runtime.Stack(buf, false)]
			err = fmt.Errorf("panic generating ssl certificate for %s: %s\n%s", addr, e, buf)
		}
	}()

	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: name, InsecureSkipVerify: true})
	if err != nil {
		return tls.Certificate{}, err
	}
	defer conn.Close()
	state := conn.ConnectionState()
	serverCert := state.PeerCertificates[0]

	// Avoid duplicate serial numbers (NSS error -8054 in Chrome).
	serverCert.SerialNumber, err = rand.Int(rand.Reader, maxSerial)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate serial number: %s", err)
	}

	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate private key: %s", err)
	}

	intermediates := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	_, err = serverCert.Verify(x509.VerifyOptions{Intermediates: intermediates})
	signingCert := parsedTLSCert
	if _, ok := err.(x509.UnknownAuthorityError); ok {
		// There was a certificate error, so generate a self-signed certificate.
		signingCert = serverCert
	}

	newCertBytes, err := x509.CreateCertificate(rand.Reader, serverCert, signingCert, &priv.PublicKey, tlsCert.PrivateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	newCert := tls.Certificate{
		Certificate: [][]byte{newCertBytes},
		PrivateKey: priv,
	}

	newCert.Certificate = append(newCert.Certificate, tlsCert.Certificate...)
	return newCert, nil
}

func readBypassFile(filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("could not open %s: %s", filename, err)
	}
	defer f.Close()
	cr := newConfigReader(f)

	for {
		line, err := cr.ReadLine()
		if err != nil {
			break
		}

		if strings.HasPrefix(line, ".") {
			// This is a domain that we should bypass subdomains of too.
			tlsBypassDomains = append(tlsBypassDomains, line)
			continue
		}

		if _, subnet, err := net.ParseCIDR(line); err == nil {
			// It's a network range, like 192.168.0.1/24.
			tlsBypassRanges = append(tlsBypassRanges, subnet)
			continue
		}

		tlsBypass[line] = true
	}

	return nil
}

func readClientHello(conn net.Conn) (hello []byte, err error) {
	var header [5]byte
	n, err := io.ReadFull(conn, header[:])
	hello = header[:n]
	if err != nil {
		return hello, err
	}

	if header[0] != 22 {
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
