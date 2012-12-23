package main

import (
	"io"
	"net"
	"net/http"
)

type proxyHandler struct{}

func (h proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Header.Add("Via", "Redwood")
	client := r.RemoteAddr
	host, _, err := net.SplitHostPort(client)
	if err == nil {
		client = host
	}
	r.Header.Add("X-Forwarded-For", client)
	r.Header.Del("Accept-Encoding")

	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	receivedHeader := resp.Header
	newHeader := w.Header()
	for key, values := range receivedHeader {
		for _, v := range values {
			newHeader.Add(key, v)
		}
	}

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}
