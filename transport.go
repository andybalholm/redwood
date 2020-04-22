package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/textproto"
	"path"
	"reflect"
	"strconv"
	"strings"
	"time"

	ftp "github.com/remogatto/ftpget"
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

var insecureHTTPTransport = &http.Transport{
	TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true,
	},
	Proxy:                 http.ProxyFromEnvironment,
	DialContext:           dialer.DialContext,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}

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
	DialTLS:               dialWithExtraRootCerts,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}

var clientWithExtraRootCerts = &http.Client{
	Transport: transportWithExtraRootCerts,
}

// A hardValidationTransport wraps another (insecure) RoundTripper and checks
// the server certificates various ways, including against an earlier
// connection's certificates. If any of the checks pass, the certificate is
// accepted.
type hardValidationTransport struct {
	rt http.RoundTripper

	originalCertificates []*x509.Certificate
	originalServerName   string

	// originalCertPool is a CertPool containing the certificates from originalCertificates
	originalCertPool *x509.CertPool

	// expectedErrDefault is the error that was received when validating the
	// original certificate against the system default CAs.
	expectedErrDefault error

	// expectedErrOriginal is the error that was received when validating
	// the original certificate against its own certificate chain.
	// It should normally be nil, but not always.
	expectedErrOriginal error
}

var errCouldNotVerify = errors.New("server certificate changed; can't verify the new certificate")

func newHardValidationTransport(rt http.RoundTripper, serverName string, certificates []*x509.Certificate) *hardValidationTransport {
	t := &hardValidationTransport{
		rt:                   rt,
		originalCertificates: certificates,
		originalServerName:   serverName,
		originalCertPool:     x509.NewCertPool(),
	}

	for _, cert := range certificates {
		t.originalCertPool.AddCert(cert)
	}

	_, t.expectedErrDefault = certificates[0].Verify(x509.VerifyOptions{
		Intermediates: t.originalCertPool,
		DNSName:       serverName,
	})

	_, t.expectedErrOriginal = certificates[0].Verify(x509.VerifyOptions{
		Roots:   t.originalCertPool,
		DNSName: serverName,
	})

	return t
}

func sameType(a, b interface{}) bool {
	return reflect.TypeOf(a) == reflect.TypeOf(b)
}

func (t *hardValidationTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "http" {
		req.URL.Scheme = "https"
	}

	resp, err := t.rt.RoundTrip(req)
	if err != nil {
		return resp, err
	}

	// Check for public key equality first, since it's cheap.
	if bytes.Equal(resp.TLS.PeerCertificates[0].RawSubjectPublicKeyInfo, t.originalCertificates[0].RawSubjectPublicKeyInfo) {
		return resp, nil
	}

	serverCert := resp.TLS.PeerCertificates[0]
	intermediates := x509.NewCertPool()
	for _, ic := range resp.TLS.PeerCertificates[1:] {
		intermediates.AddCert(ic)
	}

	_, err = serverCert.Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		DNSName:       req.Host,
	})
	if err == nil || sameType(err, t.expectedErrDefault) {
		return resp, nil
	}

	_, err = serverCert.Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		DNSName:       req.Host,
		Roots:         t.originalCertPool,
	})
	if err == nil || sameType(err, t.expectedErrOriginal) {
		return resp, nil
	}

	if req.Host != t.originalServerName {
		_, err := serverCert.Verify(x509.VerifyOptions{
			Intermediates: intermediates,
			DNSName:       t.originalServerName,
		})
		if err == nil || sameType(err, t.expectedErrDefault) {
			return resp, nil
		}

		_, err = serverCert.Verify(x509.VerifyOptions{
			Intermediates: intermediates,
			DNSName:       t.originalServerName,
			Roots:         t.originalCertPool,
		})
		if err == nil || sameType(err, t.expectedErrOriginal) {
			return resp, nil
		}
	}

	resp.Body.Close()
	return resp, errCouldNotVerify
}

// A simpleTransport fetches a single file over plain HTTP, as simply as
// possible.
type simpleTransport struct{}

func (simpleTransport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	if req.Method != "GET" {
		return nil, fmt.Errorf("request method not supported by simpleTransport (expected GET, got %s)", req.Method)
	}
	if req.URL.Scheme != "http" {
		return nil, fmt.Errorf("URL scheme not supported by simpleTransport (expected http, got %s)", req.URL.Scheme)
	}

	host := req.URL.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "80")
	}

	conn, err := dialer.Dial("tcp", host)
	if err != nil {
		return nil, fmt.Errorf("error connecting to %s: %v", host, err)
	}
	if err = req.Write(conn); err != nil {
		return nil, fmt.Errorf("error sending request for %v: %v", req.URL, err)
	}

	br := bufio.NewReader(conn)
	tp := textproto.NewReader(br)
	resp = &http.Response{
		Request: req,
	}

	// Parse the first line of the response.
	line, err := tp.ReadLine()
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	if i := strings.IndexByte(line, ' '); i == -1 {
		return nil, fmt.Errorf("malformed HTTP response: %q", line)
	} else {
		resp.Proto = line[:i]
		resp.Status = strings.TrimLeft(line[i+1:], " ")
	}
	statusCode := resp.Status
	if i := strings.IndexByte(resp.Status, ' '); i != -1 {
		statusCode = resp.Status[:i]
	}
	if len(statusCode) != 3 {
		return nil, fmt.Errorf("malformed HTTP status code: %q", statusCode)
	}
	resp.StatusCode, err = strconv.Atoi(statusCode)
	if err != nil || resp.StatusCode < 0 {
		return nil, fmt.Errorf("malformed HTTP status code: %q", statusCode)
	}
	var ok bool
	if resp.ProtoMajor, resp.ProtoMinor, ok = http.ParseHTTPVersion(resp.Proto); !ok {
		return nil, fmt.Errorf("malformed HTTP version: %q", resp.Proto)
	}

	// Parse the response headers.
	mimeHeader, err := tp.ReadMIMEHeader()
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	resp.Header = http.Header(mimeHeader)

	cl := resp.Header.Get("Content-Length")
	if cl != "" {
		if resp.ContentLength, err = strconv.ParseInt(cl, 10, 64); err != nil {
			return nil, fmt.Errorf("invalid Content-Length: %q", cl)
		}
	}
	resp.Header.Del("Content-Length")
	resp.Header.Del("Trailer")

	var body struct {
		io.Reader
		io.Closer
	}
	body.Reader = &io.LimitedReader{br, resp.ContentLength}
	body.Closer = conn
	resp.Body = body

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
