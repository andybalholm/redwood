package main

// scanning an HTTP response for phrases

import (
	"code.google.com/p/mahonia"
	"compress/gzip"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"unicode/utf8"
)

// shouldScanPhrases returns true if Redwood should run a phrase 
// scan on an HTTP response. preview should be the first bytes of 
// content.
func shouldScanPhrases(r *http.Response, preview []byte) bool {
	contentType := strings.ToLower(r.Header.Get("Content-Type"))
	semicolon := strings.Index(contentType, ";")
	if semicolon != -1 {
		contentType = contentType[:semicolon]
	}
	contentType = strings.TrimSpace(contentType)
	if !strings.Contains(contentType, "/") {
		contentType = ""
	}

	switch contentType {
	case "text/css":
		return false
	case "text/plain", "text/html", "unknown/unknown", "application/unknown", "*/*", "", "application/octet-stream":
		// These types tend to be used for content whose type is unknown,
		// so we should try to second-guess them.
		if e := r.Header.Get("Content-Encoding"); e == "" || e == "identity" {
			contentType = http.DetectContentType(preview)
		}
	case "application/json", "application/javascript", "application/x-javascript":
		// Some sites put their content in JavaScript or JSON, so we need to scan those,
		// however much we would like not to.
		return true
	}

	return strings.Contains(contentType, "text")
}

// scanContent scans the content of a document for phrases,
// and updates its counts and scores.
func (c *context) scanContent() {
	if c.charset == "" {
		c.findCharset()
	}
	decode := mahonia.NewDecoder(c.charset)
	if decode == nil {
		log.Printf("Unsupported charset (%s) on %s", c.charset, c.URL)
		decode = mahonia.NewDecoder("utf-8")
	}
	if strings.Contains(c.contentType, "html") {
		decode = mahonia.FallbackDecoder(mahonia.EntityDecoder(), decode)
	}

	content := c.content

	ps := newPhraseScanner()
	ps.scanByte(' ')
	prevRune := ' '
	var buf [4]byte // buffer for UTF-8 encoding of runes

loop:
	for len(content) > 0 {
		// Read one Unicode character from content.
		c, size, status := decode(content)
		content = content[size:]
		switch status {
		case mahonia.STATE_ONLY:
			continue
		case mahonia.NO_ROOM:
			break loop
		}

		// Simplify it to lower-case words separated by single spaces.
		c = wordRune(c)
		if c == ' ' && prevRune == ' ' {
			continue
		}
		prevRune = c

		// Convert it to UTF-8 and scan the bytes.
		if c < 128 {
			ps.scanByte(byte(c))
			continue
		}
		n := utf8.EncodeRune(buf[:], c)
		for _, b := range buf[:n] {
			ps.scanByte(b)
		}
	}

	ps.scanByte(' ')

	for rule, n := range ps.tally {
		c.tally[rule] += n
	}
	c.calculateScores()
}

// responseContent reads the body of an HTTP response into a slice of bytes.
// It decompresses gzip-encoded responses.
func responseContent(res *http.Response) []byte {
	r := res.Body
	defer r.Close()

	if res.Header.Get("Content-Encoding") == "gzip" {
		log.Println("Using gzip decoder.")
		gz, err := gzip.NewReader(r)
		if err != nil {
			panic(fmt.Errorf("could not create gzip decoder: %s", err))
		}
		defer gz.Close()
		r = gz
		res.Header.Del("Content-Encoding")
	}

	content, _ := ioutil.ReadAll(r)
	// Deliberately ignore the error. ebay.com searches produce errors, but work.

	return content
}
