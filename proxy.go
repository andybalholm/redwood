package main

import (
	"io"
	"net"
	"net/http"
)

type proxyHandler struct{}

func (h proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Host == "203.0.113.1" {
		http.DefaultServeMux.ServeHTTP(w, r)
		return
	}

	r.Header.Add("Via", "Redwood")
	client := r.RemoteAddr
	host, _, err := net.SplitHostPort(client)
	if err == nil {
		client = host
	}
	r.Header.Add("X-Forwarded-For", client)
	r.Header.Del("Accept-Encoding")

	// Reconstruct the URL if this is a transparent proxy.
	if r.URL.Host == "" {
		r.URL.Host = r.Host
		if r.URL.Scheme == "" {
			r.URL.Scheme = "http"
			// TODO: handle HTTPS
		}
	}

	sc := scorecard{
		tally: URLRules.MatchingRules(r.URL),
	}
	sc.calculate(client)
	if sc.action == BLOCK {
		showBlockPage(w, r, &sc)
		return
	}

	changeQuery(r.URL)

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
