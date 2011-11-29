package main

import (
	"fmt"
	"go-icap.googlecode.com/hg"
	"log"
	"mime"
	"path"
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
		h.Set("Preview", "4096")
		w.WriteHeader(200, nil, false)

	case "RESPMOD":
		contentType := req.Response.Header.Get("Content-Type")
		if contentType == "" {
			contentType = mime.TypeByExtension(strings.ToLower(path.Ext(req.Request.URL.Path)))
			if i := strings.Index(contentType, ";"); i != -1 {
				// Strip off (probably incorrect) charset.
				contentType = contentType[:i]
			}
		}

		a := actionForContentType(contentType)

		if a == ALLOW {
			w.WriteHeader(204, nil, false)
			log.Println("Allow content by MIME type:", req.Request.URL, contentType)
			return
		}

		if a == BLOCK {
			showBlockPage(w, []string{fmt.Sprintf("banned content type: %s", contentType)}, req.Request.URL, req.Header.Get("X-Client-IP"))
			log.Println("BLOCK content by MIME type:", req.Request.URL, contentType)
			return
		}

		urlTally := URLRules.MatchingRules(req.Request.URL)
		content := responseContent(req.Response)
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

// actionForContentType returns the action implied by the response's 
// Content-Type header. If it returns IGNORE, the content type doesn't
// dictate an action, so the content should be scanned with the phrase filter.
func actionForContentType(t string) action {
	if strings.Contains(t, "text/css") {
		return ALLOW
	}
	if strings.Contains(t, "text") {
		return IGNORE
	}
	return ALLOW
}
