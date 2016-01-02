package main

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"path"
	"time"

	"github.com/remogatto/ftpget"
	"golang.org/x/net/http2"
)

var dialer = &net.Dialer{
	Timeout:   30 * time.Second,
	KeepAlive: 30 * time.Second,
}

var httpTransport = &http.Transport{
	Proxy:                 http.ProxyFromEnvironment,
	Dial:                  dialer.Dial,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}

func init() {
	httpTransport.RegisterProtocol("ftp", FTPTransport{})
}

var insecureHTTPTransport = &http.Transport{
	TLSClientConfig:       unverifiedClientConfig,
	Proxy:                 http.ProxyFromEnvironment,
	Dial:                  dialer.Dial,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}

var http2Transport = &http2.Transport{
	DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
		return tls.DialWithDialer(dialer, network, addr, cfg)
	},
}

var insecureHTTP2Transport = &http2.Transport{
	TLSClientConfig: unverifiedClientConfig,
	DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
		return tls.DialWithDialer(dialer, network, addr, cfg)
	},
}

// A pinnedTransport wraps another RoundTripper and ensures that the
// certificates' public keys match.
type pinnedTransport struct {
	// rt is the underlying RoundTripper.
	rt http.RoundTripper

	// key is the RawSubjectPublicKeyInfo that the certificates need to match.
	key []byte
}

var errPublicKeyMismatch = errors.New("certificate public key changed since first connection to server")

func (p *pinnedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := p.rt.RoundTrip(req)
	if err != nil {
		return resp, err
	}

	if !bytes.Equal(resp.TLS.PeerCertificates[0].RawSubjectPublicKeyInfo, p.key) {
		resp.Body.Close()
		return nil, errPublicKeyMismatch
	}

	return resp, nil
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
