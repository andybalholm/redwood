package main

// scanning an HTTP response for phrases

import (
	"bytes"
	"code.google.com/p/go.net/html/charset"
	"code.google.com/p/go.text/transform"
	"compress/gzip"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

var contentPhraseList = newPhraseList()

// scanContent scans the content of a document for phrases,
// and updates tally.
func scanContent(content []byte, contentType, cs string, tally map[rule]int) {
	if strings.Contains(contentType, "javascript") {
		scanJSContent(content, tally)
		return
	}

	transformers := make([]transform.Transformer, 0, 3)
	if cs != "utf-8" {
		e, _ := charset.Lookup(cs)
		transformers = append(transformers, e.NewDecoder())
	}

	if strings.Contains(contentType, "html") {
		transformers = append(transformers, entityDecoder{})
	}
	transformers = append(transformers, new(wordTransformer))

	ps := newPhraseScanner(contentPhraseList, func(s string) {
		tally[rule{t: contentPhrase, content: s}]++
	})
	ps.scanByte(' ')

	var t transform.Transformer
	if len(transformers) == 1 {
		t = transformers[0]
	} else {
		t = transform.Chain(transformers...)
	}

	buf := make([]byte, 4096)
	for len(content) > 0 {
		nDst, nSrc, err := t.Transform(buf, content, true)
		if nSrc == 0 && nDst == 0 {
			panic(err)
		}
		for _, c := range buf[:nDst] {
			ps.scanByte(c)
		}
		content = content[nSrc:]
	}

	ps.scanByte(' ')
}

// scanJSContent scans only the contents of quoted JavaScript strings
// in the document.
func scanJSContent(content []byte, tally map[rule]int) {
	_, items := lex(string(content))
	ps := newPhraseScanner(contentPhraseList, func(s string) {
		tally[rule{t: contentPhrase, content: s}]++
	})

	for s := range items {
		s = wordString(s)
		ps.scanByte(' ')
		for i := 0; i < len(s); i++ {
			ps.scanByte(s[i])
		}
		ps.scanByte(' ')
	}
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
