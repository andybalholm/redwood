package main

import (
	"go-icap.googlecode.com/hg"
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
		h.Set("Allow", "204")
		h.Set("Transfer-Complete", "*")
		if binaryTypesString != "" {
			h.Set("Transfer-Ignore", binaryTypesString)
		}
		w.WriteHeader(200, nil, false)

	case "RESPMOD":
		urlTally := URLRules.MatchingRules(req.Request.URL)

		content := responseContent(req.Response)
		contentType := req.Response.Header.Get("Content-Type")
		pageTally := phrasesInResponse(content, contentType)

		for rule, n := range urlTally {
			pageTally[rule] += n
		}
		if len(pageTally) > 0 {
			scores := categoryScores(pageTally)
			if len(scores) > 0 {
				blocked := blockedCategories(scores)
				if len(blocked) > 0 {
					showBlockPage(w, blocked, req.Request.URL, req.Header.Get("X-Client-IP"))
					log.Println("BLOCK content:", req.Request.URL)
					return
				}
			}
		}

		rw := icap.NewBridgedResponseWriter(w)
		oldHeaders := req.Response.Header
		newHeaders := rw.Header()
		for key, val := range oldHeaders {
			newHeaders[key] = val
		}
		rw.WriteHeader(req.Response.StatusCode)
		rw.Write(content)
		log.Println("Allow content:", req.Request.URL)

	default:
		w.WriteHeader(405, nil, false)
	}
}
