package main

// scanning an HTTP response for phrases

import (
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

	buf := make([]byte, 4096)
	for len(content) > 0 {
		nDst, nSrc, err := t.Transform(buf, content, true)
		if nSrc == 0 && nDst == 0 {
			if err == transform.ErrShortSrc {
				log.Printf("Encountered ErrShortSrc while decoding page content; remaining content: %q", content)
			} else {
				log.Println("Error decoding page content:", err)
			}
			nSrc = len(content)
			nDst = nSrc
			copy(buf, content)
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
