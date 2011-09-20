package main

import (
	"fmt"
	"go-icap.googlecode.com/hg"
	"http"
	"log"
	"time"
)

// Request-modification functions.

var ISTag = fmt.Sprintf("Redwood%d", time.Nanoseconds())

func handleRequest(w icap.ResponseWriter, req *icap.Request) {
	h := w.Header()
	h.Set("ISTag", ISTag)
	h.Set("Service", "Redwood content filter")

	switch req.Method {
	case "OPTIONS":
		h.Set("Methods", "REQMOD")
		h.Set("Allow", "204")
		w.WriteHeader(200, nil, false)

	case "REQMOD":
		urlTally := URLRules.MatchingRules(req.Request.URL)
		if len(urlTally) > 0 {
			urlScores := categoryScores(urlTally)
			if len(urlScores) > 0 {
				blocked := blockedCategories(urlScores)
				if len(blocked) > 0 {
					showBlockPage(w, blocked)
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

func showBlockPage(w icap.ResponseWriter, blocked []string) {
	rw := icap.NewBridgedResponseWriter(w)
	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
	rw.WriteHeader(http.StatusForbidden)
	fmt.Fprint(rw, "This page is blocked by Redwood.\r\n\r\n")
	fmt.Fprint(rw, "Catgories:\r\n")
	for _, c := range blocked {
		fmt.Fprint(rw, c, "\r\n")
	}
}
