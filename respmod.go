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
		pageTally := phrasesInResponse(req.Response)
		for rule, n := range urlTally {
			pageTally[rule] += n
		}
		if len(pageTally) > 0 {
			scores := categoryScores(pageTally)
			if len(scores) > 0 {
				blocked := blockedCategories(scores)
				if len(blocked) > 0 {
					showBlockPage(w, blocked)
					log.Println("BLOCK content:", req.Request.URL)
					return
				}
			}
		}

		w.WriteHeader(204, nil, false)
		log.Println("Allow content:", req.Request.URL)

	default:
		w.WriteHeader(405, nil, false)
	}
}
