package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"path"
	"sync"
	"time"

	ftp "github.com/remogatto/ftpget"
	"golang.org/x/net/http2"
)

var dialer = &net.Dialer{
	Timeout:   30 * time.Second,
	KeepAlive: 30 * time.Second,
	DualStack: true,
}

var httpTransport = &http.Transport{
	Proxy:                 http.ProxyFromEnvironment,
	DialContext:           dialer.DialContext,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}

func init() {
	httpTransport.RegisterProtocol("ftp", FTPTransport{})
}

var http2Transport = &http2.Transport{}

func dialWithExtraRootCerts(network, addr string) (net.Conn, error) {
	// Dial a TLS connection, and make sure it is valid against either the system default
	// roots or conf.ExtraRootCerts.
	serverName, _, _ := net.SplitHostPort(addr)
	conn, err := tls.DialWithDialer(dialer, network, addr, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, err
	}
	state := conn.ConnectionState()
	serverCert := state.PeerCertificates[0]

	chains, err := serverCert.Verify(x509.VerifyOptions{
		Intermediates: certPoolWith(state.PeerCertificates[1:]),
		DNSName:       serverName,
	})
	if err == nil {
		state.VerifiedChains = chains
		return conn, nil
	}

	if conf := getConfig(); conf.ExtraRootCerts != nil {
		chains, err = serverCert.Verify(x509.VerifyOptions{
			Intermediates: certPoolWith(state.PeerCertificates[1:]),
			DNSName:       serverName,
			Roots:         conf.ExtraRootCerts,
		})
		if err == nil {
			state.VerifiedChains = chains
			return conn, nil
		}
	}

	conn.Close()
	return nil, err
}

var transportWithExtraRootCerts = &http.Transport{
	DialTLS: dialWithExtraRootCerts,
}

// A connTransport is an http.RoundTripper that uses a single network
// connection.
type connTransport struct {
	Conn net.Conn

	// Done specifies an optional callback function that is called when the
	// connection is no longer readable. If the read fails with an error other
	// than io.EOF, the error is passed to Done.
	Done func(error)

	once sync.Once
	br   *bufio.Reader
}

func (ct *connTransport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	ctx := req.Context()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		// Continue.
	}

	ct.once.Do(ct.initialize)

	if err := req.Write(ct.Conn); err != nil {
		return nil, err
	}

	resp, err = http.ReadResponse(ct.br, req)
	if err == nil {
		resp.Body = &bodyWithContext{
			ReadCloser: resp.Body,
			Ctx:        ctx,
		}
	}
	return resp, err
}

func (ct *connTransport) initialize() {
	// Set up the reader goroutine.
	//
	// In order to detact as soon as possible if Conn is closed or otherwise
	// unusable, we constantly read from it in a goroutine, and pass the data
	// through a pipe to the actual reader used in ReadResponse.
	pr, pw := io.Pipe()
	ct.br = bufio.NewReader(pr)

	go func() {
		_, err := io.Copy(pw, ct.Conn)
		if ct.Done != nil {
			ct.Done(err)
		}
		pw.CloseWithError(err)
	}()
}

// A bodyWithContext wraps a response body, and makes Read return an error if
// the associated context is canceled.
type bodyWithContext struct {
	io.ReadCloser
	Ctx context.Context
}

func (b *bodyWithContext) Read(p []byte) (n int, err error) {
	select {
	case <-b.Ctx.Done():
		return 0, b.Ctx.Err()
	default:
		return b.ReadCloser.Read(p)
	}
}

// An FTPTransport fetches files via FTP.
type FTPTransport struct{}

func (FTPTransport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	if req.Method != "GET" {
		return &http.Response{
			StatusCode: http.StatusMethodNotAllowed,
			Request:    req,
		}, nil
	}

	fullPath := req.URL.Host + req.URL.Path
	r, w := io.Pipe()
	xfer, err := ftp.GetAsync(fullPath, w)
	if err != nil {
		return nil, err
	}

	go func() {
		for stat := range xfer.Status {
			switch stat {
			case ftp.COMPLETED:
				w.Close()
				return
			case ftp.ERROR:
				err := <-xfer.Error
				log.Printf("FTP: error downloading %v: %v", req.URL, err)
				w.CloseWithError(err)
				return
			}
		}
	}()

	resp = &http.Response{
		StatusCode: 200,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Request:    req,
		Body:       r,
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
