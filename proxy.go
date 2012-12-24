package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
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
	defer resp.Body.Close()

	contentType, action := checkContentType(resp)

	switch action {
	case BLOCK:
		sc.action = BLOCK
		sc.blocked = []string{"blocked-mime"}
		showBlockPage(w, r, &sc)
		return

	case ALLOW:
		copyResponseHeader(w, resp)
		io.Copy(w, resp.Body)
		return
	}

	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(fmt.Errorf("error while reading response body: %s", err))
	}

	modified := false
	charset := findCharset(resp.Header.Get("Content-Type"), content)
	if strings.Contains(contentType, "html") {
		modified = pruneContent(r.URL, &content, charset)
		if modified {
			resp.Header.Set("Content-Type", "text/html; charset=utf-8")
			charset = "utf-8"
		}
	}

	scanContent(content, contentType, charset, sc.tally)
	sc.calculate(client)

	if sc.action == BLOCK {
		showBlockPage(w, r, &sc)
		return
	}

	copyResponseHeader(w, resp)
	w.Write(content)
}

// copyResponseHeader writes resp's header and status code to w.
func copyResponseHeader(w http.ResponseWriter, resp *http.Response) {
	newHeader := w.Header()
	for key, values := range resp.Header {
		for _, v := range values {
			newHeader.Add(key, v)
		}
	}

	w.WriteHeader(resp.StatusCode)
}
