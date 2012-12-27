package main

import (
	"crypto/tls"
)

// Cache generated TLS certificates.

type certRequest struct {
	// serverAddress is the address (host:port) of the server.
	serverAddress string

	// responseChan is a channel to send the response on.
	responseChan chan certResponse
}

type certResponse struct {
	// serverAddress is the address of the server this certificate is for.
	serverAddress string

	// cert is the certificate that was generated.
	cert tls.Certificate

	// err is any error that was encountered while generating the certificate.
	err error
}

var certRequestChan = make(chan certRequest)

// cacheCertificates runs the certificate cache. It should be run in its own
// goroutine.
func cacheCertificates() {
	cache := map[string]certResponse{}
	pending := map[string][]certRequest{}
	responses := make(chan certResponse)

	for {
		select {
		case req := <-certRequestChan:
			addr := req.serverAddress
			if resp, ok := cache[addr]; ok {
				req.responseChan <- resp
				continue
			}
			if _, ok := pending[addr]; !ok {
				go func() {
					cert, err := generateCertificate(addr)
					responses <- certResponse{
						serverAddress: addr,
						cert:          cert,
						err:           err,
					}
				}()
			}
			pending[addr] = append(pending[addr], req)

		case resp := <-responses:
			addr := resp.serverAddress
			for _, req := range pending[addr] {
				req.responseChan <- resp
			}
			delete(pending, addr)
			cache[addr] = resp
		}
	}
}

// getCertificate is like generateCertificate, except that it uses the cache.
func getCertificate(addr string) (tls.Certificate, error) {
	responseChan := make(chan certResponse)
	certRequestChan <- certRequest{
		serverAddress: addr,
		responseChan:  responseChan,
	}
	resp := <-responseChan
	return resp.cert, resp.err
}
