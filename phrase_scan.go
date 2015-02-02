package main

// scanning an HTTP response for phrases

import (
	"bytes"
	"io"
	"log"
	"strings"

	"golang.org/x/net/html/charset"
	"golang.org/x/text/transform"
)

// scanContent scans the content of a document for phrases,
// and updates tally.
func (conf *config) scanContent(content []byte, contentType, cs string, tally map[rule]int) {
	if strings.Contains(contentType, "javascript") {
		conf.scanJSContent(content, tally)
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

	ps := newPhraseScanner(conf.ContentPhraseList, func(s string) {
		tally[rule{t: contentPhrase, content: s}]++
	})
	ps.scanByte(' ')

	var t transform.Transformer
	if len(transformers) == 1 {
		t = transformers[0]
	} else {
		t = transform.Chain(transformers...)
	}

	r := transform.NewReader(bytes.NewReader(content), t)

	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		for _, c := range buf[:n] {
			ps.scanByte(c)
		}
		if err != nil {
			if err != io.EOF {
				log.Println("Error decoding page content:", err)
			}
			break
		}
	}

	ps.scanByte(' ')
}

// scanJSContent scans only the contents of quoted JavaScript strings
// in the document.
func (conf *config) scanJSContent(content []byte, tally map[rule]int) {
	_, items := lex(string(content))
	ps := newPhraseScanner(conf.ContentPhraseList, func(s string) {
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
