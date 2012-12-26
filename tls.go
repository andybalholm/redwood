package main

import (
	"crypto/tls"
	"flag"
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
var tlsReady bool

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
		tlsReady = true
	}
}

// SSLBump performs a man-in-the-middle attack on conn, to filter the HTTPS
// traffic. serverAddr is the address (host:port) of the server the client was
// trying to connect to.
func SSLBump(conn net.Conn, serverAddr string) {
	config := &tls.Config{
		NextProtos:   []string{"http/1.1"},
		Certificates: []tls.Certificate{tlsCert},
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
