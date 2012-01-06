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

		c := context{
			URL:  req.Request.URL,
			user: req.Header.Get("X-Client-IP"),
		}

		c.scanURL()

		if c.action == BLOCK {
			showBlockPage(w, c.blocked, c.URL, c.user)
			log.Println("BLOCK URL:", c.URL)
			return
		}

		w.WriteHeader(204, nil, false)
		log.Println("Allow URL:", c.URL)

	default:
		w.WriteHeader(405, nil, false)
	}
}

// scanURL calculates scores and an action based on the request's URL.
func (c *context) scanURL() {
	c.tally = URLRules.MatchingRules(c.URL)
	c.calculateScores()
}