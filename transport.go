package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"github.com/jlaffaye/goftp"
	"io"
	"mime"
	"net"
	"net/http"
	"path"
	"sync"
	"time"
)

// A TLSRedialTransport is an http.RoundTripper that sends all the requests
// over a TLS connection to one server. It will automatically reconnect to the
// server as needed.
type TLSRedialTransport struct {
	http.Transport

	// ServerConn is the initial connection to the server.
	ServerConn *tls.Conn

	// ServerName is the SNI to send when reconnecting.
	ServerName string

	serverAddr string
	publicKey  []byte
	once       sync.Once
	timeout    *time.Timer
}

func NewTLSRedialTransport(conn *tls.Conn, serverName string) *TLSRedialTransport {
	t := &TLSRedialTransport{
		ServerConn: conn,
		ServerName: serverName,
		serverAddr: conn.RemoteAddr().String(),
		publicKey:  conn.ConnectionState().PeerCertificates[0].RawSubjectPublicKeyInfo,
	}

	t.Dial = t.dial
	t.timeout = time.AfterFunc(10*time.Second, t.CloseIdleConnections)

	return t
}

func (t *TLSRedialTransport) dial(network, addr string) (conn net.Conn, err error) {
	t.once.Do(func() {
		conn = t.ServerConn
	})
	if conn != nil {
		return conn, nil
	}

	newConn, err := tls.Dial("tcp", t.serverAddr, &tls.Config{
		ServerName:         t.ServerName,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(t.publicKey, newConn.ConnectionState().PeerCertificates[0].RawSubjectPublicKeyInfo) {
		newConn.Close()
		return nil, fmt.Errorf("TLS private key at %s changed", t.ServerName)
	}

	return newConn, nil
}

func (t *TLSRedialTransport) CloseIdleConnections() {
	// If the Once hasn't fired yet, the original connection hasn't been used.
	t.once.Do(func() {
		t.ServerConn.Close()
	})

	t.Transport.CloseIdleConnections()
}

func (t *TLSRedialTransport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	// Temporarily change the scheme to HTTP, since we're taking care of TLS
	// and we don't want the underlying Transport to try to do TLS too.
	realScheme := req.URL.Scheme
	req.URL.Scheme = "http"

	resp, err = t.Transport.RoundTrip(req)
	req.URL.Scheme = realScheme

	if !t.timeout.Reset(10 * time.Second) {
		t.timeout = time.AfterFunc(10*time.Second, t.CloseIdleConnections)
	}

	return
}

// An FTPTransport fetches files via FTP.
type FTPTransport struct{}

func (FTPTransport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	addr := req.URL.Host
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "21")
	}

	server, err := ftp.Connect(addr)
	if err != nil {
		return nil, err
	}

	err = server.Login("anonymous", "anonymous")
	if err != nil {
		server.Quit()
		return nil, err
	}

	body, err := server.Retr(req.URL.Path)
	if err != nil {
		server.Quit()
		return nil, err
	}

	resp = &http.Response{
		StatusCode: 200,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Request:    req,
		Body:       closeQuitter{body, server},
		Header:     make(http.Header),
	}

	ext := path.Ext(req.URL.Path)
	if ext != "" {
		ct := mime.TypeByExtension(ext)
		if ct != "" {
			resp.Header.Set("Content-Type", ct)
		}
	}

	return resp, nil
}

type closeQuitter struct {
	io.ReadCloser
	server *ftp.ServerConn
}

func (c closeQuitter) Close() error {
	err := c.ReadCloser.Close()
	err2 := c.server.Quit()

	if err == nil {
		err = err2
	}
	return err
}
