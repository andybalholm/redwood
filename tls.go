package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
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
func connectDirect(conn net.Conn, serverAddr string) {
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
// trying to connect to.
func SSLBump(conn net.Conn, serverAddr string) {
	defer func() {
		if err := recover(); err != nil {
			buf := make([]byte, 4096)
			buf = buf[:runtime.Stack(buf, false)]
			log.Printf("SSLBump: panic serving connection to %s: %v\n%s", serverAddr, err, buf)
			conn.Close()
		}
	}()

	if host, _, err := net.SplitHostPort(serverAddr); err == nil && shouldBypass(host) {
		connectDirect(conn, serverAddr)
		return
	}

	if *tlsVerbose {
		log.Printf("intercepting TLS connection from %s to %s", conn.RemoteAddr(), serverAddr)
	}

	cert, err := getCertificate(serverAddr)
	if err != nil {
		// Since it doesn't seem to be an HTTPS server, just connect directly.
		log.Printf("Could not generate a TLS certificate for %s (%s); letting the client connect directly", serverAddr, err)
		connectDirect(conn, serverAddr)
		return
	}

	config := &tls.Config{
		NextProtos:   []string{"http/1.1"},
		Certificates: []tls.Certificate{cert, tlsCert},
	}

	tlsConn := tls.Server(conn, config)
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
		},
	}
	server.Serve(listener)
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
// connections to that server.
func generateCertificate(addr string) (cert tls.Certificate, err error) {
	defer func() {
		if e := recover(); e != nil {
			buf := make([]byte, 4096)
			buf = buf[:runtime.Stack(buf, false)]
			err = fmt.Errorf("panic generating ssl certificate for %s: %s\n%s", addr, e, buf)
		}
	}()

	conn, err := tls.Dial("tcp", addr, unverifiedClientConfig)
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

	certBuf := new(bytes.Buffer)
	pem.Encode(certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: newCertBytes})
	keyBuf := new(bytes.Buffer)
	pem.Encode(keyBuf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	newCert, err := tls.X509KeyPair(certBuf.Bytes(), keyBuf.Bytes())
	if err != nil {
		return tls.Certificate{}, err
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
