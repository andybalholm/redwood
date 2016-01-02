package main

import (
	"io"
	"log"
	"mime"
	"net/http"
	"path"

	"github.com/remogatto/ftpget"
	"golang.org/x/net/http2"
)

var httpTransport = &http.Transport{
	Proxy: http.ProxyFromEnvironment,
}

func init() {
	httpTransport.RegisterProtocol("ftp", FTPTransport{})
}

var insecureHTTPTransport = &http.Transport{
	TLSClientConfig: unverifiedClientConfig,
	Proxy:           http.ProxyFromEnvironment,
}

var http2Transport = &http2.Transport{}

var insecureHTTP2Transport = &http2.Transport{
	TLSClientConfig: unverifiedClientConfig,
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
