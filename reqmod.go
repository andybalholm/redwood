package main

import (
	"code.google.com/p/go-icap"
	"fmt"
	"log"
	"time"
)

// Request-modification functions.

var ISTag = fmt.Sprintf("Redwood%d", time.Now())

func handleRequest(w icap.ResponseWriter, req *icap.Request) {
	h := w.Header()
	h.Set("ISTag", ISTag)
	h.Set("Service", "Redwood content filter")

	switch req.Method {
	case "OPTIONS":
		h.Set("Methods", "REQMOD")
		h.Set("Transfer-Preview", "*")
		h.Set("Preview", "0")
		w.WriteHeader(200, nil, false)

	case "REQMOD":
		if req.Request.Host == "gateway" {
			icap.ServeLocally(w, req)
			return
		}

		urlTally := URLRules.MatchingRules(req.Request.URL)
		if len(urlTally) > 0 {
			urlScores := categoryScores(urlTally)
			if len(urlScores) > 0 {
				blocked := blockedCategories(urlScores)
				if len(blocked) > 0 {
					showBlockPage(w, blocked, req.Request.URL, req.Header.Get("X-Client-IP"))
					log.Println("BLOCK URL:", req.Request.URL)
					return
				}
			}
		}

		w.WriteHeader(204, nil, false)
		log.Println("Allow URL:", req.Request.URL)

	default:
		w.WriteHeader(405, nil, false)
	}
}
