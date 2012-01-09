package main

import (
	"code.google.com/p/go-icap"
	"log"
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
		c := context{
			URL:         req.Request.URL,
			resp:        req.Response,
			user:        req.Header.Get("X-Client-IP"),
			contentType: req.Response.Header.Get("Content-Type"),
		}

		if !shouldScanPhrases(req.Response, req.Preview) {
			c.action = IGNORE
			w.WriteHeader(204, nil, false)
			log.Println("Don't scan content:", req.Request.URL)
			return
		}

		c.scanURL()
		c.content = responseContent(c.resp)
		c.pruneContent()
		c.scanContent()

		if c.action == BLOCK {
			showBlockPage(w, c.blocked, c.URL, c.user)
			log.Println("BLOCK content:", c.URL)
			return
		}

		rw := icap.NewBridgedResponseWriter(w)
		oldHeaders := req.Response.Header
		newHeaders := rw.Header()
		for key, val := range oldHeaders {
			newHeaders[key] = val
		}
		rw.WriteHeader(req.Response.StatusCode)
		rw.Write(c.content)
		log.Println("Allow content:", c.URL)

	default:
		w.WriteHeader(405, nil, false)
	}
}
