package main

import (
	"code.google.com/p/go-icap"
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
			icapRequest: req,
			request:     req.Request,
			response:    req.Response,
		}

		c.checkContentType()

		if c.action == ALLOW {
			c.action = IGNORE
			w.WriteHeader(204, nil, false)
			logChan <- &c
			return
		}

		if c.action == BLOCK {
			c.blocked = []string{"blocked-mime"}
		}

		if c.action == FILTER {
			c.scanURL()
			c.content = responseContent(c.response)
			c.pruneContent()
			c.scanContent()
		}

		if c.action == BLOCK {
			c.showBlockPage(w)
			logChan <- &c
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
		logChan <- &c

	default:
		w.WriteHeader(405, nil, false)
	}
}
