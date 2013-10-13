package main

import (
	"crypto/tls"
)

// Cache generated TLS certificates.

type serverId struct {
	// serverAddress is the address (host:port) of the server.
	serverAddress string

	// serverName is the Server Name Indication used in the TLS client hello.
	serverName string
}

type certRequest struct {
	serverId

	// responseChan is a channel to send the response on.
	responseChan chan certResponse
}

type certResponse struct {
	serverId

	// cert is the certificate that was generated.
	cert tls.Certificate

	// err is any error that was encountered while generating the certificate.
	err error
}

var certRequestChan = make(chan certRequest)

// cacheCertificates runs the certificate cache. It should be run in its own
// goroutine.
func cacheCertificates() {
	cache := map[serverId]certResponse{}
	pending := map[serverId][]certRequest{}
	responses := make(chan certResponse)

	for {
		select {
		case req := <-certRequestChan:
			id := req.serverId
			if resp, ok := cache[id]; ok {
				req.responseChan <- resp
				continue
			}
			if _, ok := pending[id]; !ok {
				go func() {
					cert, err := generateCertificate(id.serverAddress, id.serverName)
					responses <- certResponse{
						serverId: id,
						cert:     cert,
						err:      err,
					}
				}()
			}
			pending[id] = append(pending[id], req)

		case resp := <-responses:
			id := resp.serverId
			for _, req := range pending[id] {
				req.responseChan <- resp
			}
			delete(pending, id)
			cache[id] = resp
		}
	}
}

// getCertificate is like generateCertificate, except that it uses the cache.
func getCertificate(addr string, name string) (tls.Certificate, error) {
	responseChan := make(chan certResponse)
	certRequestChan <- certRequest{
		serverId:     serverId{addr, name},
		responseChan: responseChan,
	}
	resp := <-responseChan
	return resp.cert, resp.err
}
