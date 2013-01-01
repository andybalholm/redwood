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
	"net"
	"net/http"
	"sync"
)

// Intercept TLS (HTTPS) connections.

var certFile = flag.String("tls-cert", "", "path to certificate for serving HTTPS")
var keyFile = flag.String("tls-key", "", "path to TLS certificate key")

var tlsCert tls.Certificate
var parsedTLSCert *x509.Certificate
var tlsReady bool

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

		go cacheCertificates()
	}
}

// SSLBump performs a man-in-the-middle attack on conn, to filter the HTTPS
// traffic. serverAddr is the address (host:port) of the server the client was
// trying to connect to.
func SSLBump(conn net.Conn, serverAddr string) {
	cert, err := getCertificate(serverAddr)
	if err != nil {
		panic(fmt.Errorf("could not generate TLS certificate for %s: %s", serverAddr, err))
	}

	config := &tls.Config{
		NextProtos:   []string{"http/1.1"},
		Certificates: []tls.Certificate{cert, tlsCert},
	}
	_, port, err := net.SplitHostPort(serverAddr)
	if err != nil {
		port = ""
	}
	listener := &singleListener{conn: conn}
	tlsListener := tls.NewListener(listener, config)
	server := http.Server{
		Handler: proxyHandler{
			TLS:         true,
			connectPort: port,
		},
	}
	server.Serve(tlsListener)
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

// generateCertificate connects to the server at addr, gets its TLS
// certificate, and returns a new certificate to be used when proxying
// connections to that server.
func generateCertificate(addr string) (tls.Certificate, error) {
	conn, err := tls.Dial("tcp", addr, unverifiedClientConfig)
	if err != nil {
		return tls.Certificate{}, err
	}
	defer conn.Close()
	state := conn.ConnectionState()
	serverCert := state.PeerCertificates[0]

	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate private key: %s", err)
	}

	newCertBytes, err := x509.CreateCertificate(rand.Reader, serverCert, parsedTLSCert, &priv.PublicKey, tlsCert.PrivateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	certBuf := new(bytes.Buffer)
	pem.Encode(certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: newCertBytes})
	keyBuf := new(bytes.Buffer)
	pem.Encode(keyBuf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return tls.X509KeyPair(certBuf.Bytes(), keyBuf.Bytes())
}
