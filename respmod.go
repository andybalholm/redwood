package main

import (
	"code.google.com/p/go-icap"
	"compress/gzip"
	"io"
	"io/ioutil"
	"log"
	"strings"
)

// Response-modification functions.

func handleResponse(w icap.ResponseWriter, req *icap.Request) {
	h := w.Header()
	h.Set("ISTag", ISTag)
	h.Set("Service", "Redwood content filter")

	switch req.Method {
	case "OPTIONS":
		h.Set("Methods", "RESPMOD")
		h.Set("Transfer-Preview", "*")
		h.Set("Preview", "512")
		w.WriteHeader(200, nil, false)

	case "RESPMOD":
		user := req.Header.Get("X-Client-Username")
		if user == "" {
			user = req.Header.Get("X-Client-IP")
		}

		sc := scorecard{
			tally: URLRules.MatchingRules(req.Request.URL),
		}
		sc.calculate(user)

		contentType, action := checkContentType(req.Response)
		switch action {
		case BLOCK:
			sc.action = BLOCK
			sc.blocked = []string{"blocked-mime"}
			showBlockPage(icap.NewBridgedResponseWriter(w), req.Request, &sc)
			logAccess(req.Request, req.Response, sc, contentType, 0, false, user)
			return

		case ALLOW:
			sc.action = IGNORE
			w.WriteHeader(204, nil, false)
			logAccess(req.Request, req.Response, sc, contentType, 0, false, user)
			return
		}

		var body io.Reader = req.Response.Body
		defer req.Response.Body.Close()
		if req.Response.Header.Get("Content-Encoding") == "gzip" {
			var err error
			body, err = gzip.NewReader(body)
			if err != nil {
				log.Println("error reading gzip-encoded response from %s: %s", req.Request.URL, err)
				w.WriteHeader(500, nil, false)
				return
			}
			req.Response.Header.Del("Content-Encoding")
		}

		content, err := ioutil.ReadAll(body)
		if err != nil {
			log.Println("error while reading response body:", err)
			return
		}

		modified := false
		charset := findCharset(req.Response.Header.Get("Content-Type"), content)
		if strings.Contains(contentType, "html") {
			modified = pruneContent(req.Request.URL, &content, charset)
			if modified {
				req.Response.Header.Set("Content-Type", "text/html; charset=utf-8")
				charset = "utf-8"
			}
		}

		scanContent(content, contentType, charset, sc.tally)
		sc.calculate(user)

		if sc.action == BLOCK {
			showBlockPage(icap.NewBridgedResponseWriter(w), req.Request, &sc)
			logAccess(req.Request, req.Response, sc, contentType, len(content), modified, user)
			return
		}

		rw := icap.NewBridgedResponseWriter(w)
		copyResponseHeader(rw, req.Response)
		rw.Write(content)
		logAccess(req.Request, req.Response, sc, contentType, len(content), modified, user)

	default:
		w.WriteHeader(405, nil, false)
	}
}
