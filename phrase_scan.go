package main

// scanning an HTTP response for phrases

import (
	"bytes"
	"code.google.com/p/mahonia"
	"compress/gzip"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"unicode/utf8"
)

// scanContent scans the content of a document for phrases,
// and updates its counts and scores.
func (c *context) scanContent() {
	mime := c.contentType()
	if strings.Contains(mime, "javascript") || strings.Contains(mime, "json") {
		c.scanJSContent()
		return
	}

	if c.charset == "" {
		c.findCharset()
	}
	decode := mahonia.NewDecoder(c.charset)
	if decode == nil {
		log.Printf("Unsupported charset (%s) on %s", c.charset, c.URL())
		decode = mahonia.NewDecoder("utf-8")
	}
	if strings.Contains(c.contentType(), "html") {
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

// scanJSContent scans only the contents of quoted JavaScript strings
// in the document.
func (c *context) scanJSContent() {
	_, items := lex(string(c.content))
	ps := newPhraseScanner()

	for s := range items {
		s = wordString(s)
		ps.scanByte(' ')
		for i := 0; i < len(s); i++ {
			ps.scanByte(s[i])
		}
		ps.scanByte(' ')
	}

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
		gzContent, err := ioutil.ReadAll(r)
		if err != nil {
			log.Printf("error reading gzipped content for %s: %s", res.Request.URL, err)
			return nil
		}
		if len(gzContent) == 0 {
			// If the compressed content is empty, decompress it to empty content.
			return nil
		}
		gz, err := gzip.NewReader(bytes.NewBuffer(gzContent))
		if err != nil {
			log.Printf("could not create gzip decoder for %s: %s", res.Request.URL, err)
			return nil
		}
		defer gz.Close()
		r = gz
		res.Header.Del("Content-Encoding")
	}

	content, _ := ioutil.ReadAll(r)
	// Deliberately ignore the error. ebay.com searches produce errors, but work.

	return content
}
