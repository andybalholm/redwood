package main

import (
	"code.google.com/p/go-icap"
	"flag"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
)

// Functions for displaying block pages.

var blockPage = flag.String("blockpage", "/etc/redwood/block.html", "path to template for block page")

var blockTemplate *template.Template

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
}

func showBlockPage(w icap.ResponseWriter, blocked []string, URL *url.URL, clientIP string) {
	blockDesc := make([]string, len(blocked))
	for i, name := range blocked {
		blockDesc[i] = categoryDescriptions[name]
	}
	data := blockData{
		URL:        URL.String(),
		Categories: strings.Join(blockDesc, ", "),
		IP:         clientIP,
	}
	rw := icap.NewBridgedResponseWriter(w)
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(http.StatusForbidden)

	err := blockTemplate.Execute(rw, data)
	if err != nil {
		log.Println("Error filling in block page template:", err)
	}
}
