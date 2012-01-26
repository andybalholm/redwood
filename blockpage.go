package main

import (
	"code.google.com/p/go-icap"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
)

// Functions for displaying block pages.

var blockPage = flag.String("blockpage", "/etc/redwood/block.html", "path to template for block page")

var blockTemplate *template.Template

// transparent1x1 is a single-pixel transparent GIF file.
const transparent1x1 = "GIF89a\x10\x00\x10\x00\x80\xff\x00\xc0\xc0\xc0\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x10\x00\x10\x00\x00\x02\x0e\x84\x8f\xa9\xcb\xed\x0f\xa3\x9c\xb4\u068b\xb3>\x05\x00;"

func loadBlockPage() {
	var err error
	blockTemplate, err = template.ParseFiles(*blockPage)
	if err != nil {
		log.Println("Could not load block page template:", err)
	}
}

type blockData struct {
	URL        string
	Categories string
	IP         string
	Tally      string
	Scores     string
}

func (c *context) showBlockPage(w icap.ResponseWriter) {
	rw := icap.NewBridgedResponseWriter(w)

	if categories[c.blocked[0]].invisible {
		// Serve an invisible image instead of the usual block page.
		rw.Header().Set("Content-Type", "image/gif")
		rw.WriteHeader(http.StatusForbidden)
		fmt.Fprint(rw, transparent1x1)
		return
	}

	blockDesc := make([]string, len(c.blocked))
	for i, name := range c.blocked {
		blockDesc[i] = categories[name].description
	}
	data := blockData{
		URL:        c.URL().String(),
		Categories: strings.Join(blockDesc, ", "),
		IP:         c.user(),
		Tally:      listTally(c.stringTally()),
		Scores:     listTally(c.scores),
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(http.StatusForbidden)

	err := blockTemplate.Execute(rw, data)
	if err != nil {
		log.Println("Error filling in block page template:", err)
	}
}
