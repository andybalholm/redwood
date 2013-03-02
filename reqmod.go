package main

import (
	"code.google.com/p/go-icap"
	"fmt"
	"io/ioutil"
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
		if req.Request.Host == "203.0.113.1" {
			icap.ServeLocally(w, req)
			return
		}

		user := req.Header.Get("X-Client-Username")
		if user == "" {
			user = req.Header.Get("X-Client-IP")
		}

		sc := scorecard{
			tally: URLRules.MatchingRules(req.Request.URL),
		}
		sc.calculate(user)
		if sc.action == BLOCK {
			showBlockPage(icap.NewBridgedResponseWriter(w), req.Request, &sc)
			logAccess(req.Request, nil, sc, "", 0, false, user)
			return
		}

		requestChanged := changeQuery(req.Request.URL)

		if requestChanged {
			content, err := ioutil.ReadAll(req.Request.Body)
			if err != nil {
				log.Println(err)
			}
			w.WriteHeader(200, req.Request, len(content) > 0)
			if len(content) > 0 {
				w.Write(content)
			}
		} else {
			w.WriteHeader(204, nil, false)
		}

	default:
		w.WriteHeader(405, nil, false)
	}
}
