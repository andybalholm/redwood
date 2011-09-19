package main

// scanning an HTTP response for phrases

import (
	"compress/gzip"
	"fmt"
	"http"
	"io"
	"log"
	"mahonia.googlecode.com/hg"
	"strings"
)

// phrasesInResponse scans the content of an http.Response for phrases,
// and returns a map of phrases and counts.
func phrasesInResponse(res *http.Response) map[string]int {
	defer res.Body.Close()

	contentType := res.Header.Get("Content-Type")

	var r io.Reader = res.Body

	if res.Header.Get("Content-Encoding") == "gzip" {
		log.Println("Using gzip decoder.")
		gz, err := gzip.NewReader(r)
		if err != nil {
			panic(fmt.Errorf("could not create gzip decoder: %s", err))
		}
		defer gz.Close()
		r = gz
	}

	wr := newWordReader(r, decoderForContentType(contentType))
	ps := newPhraseScanner()
	ps.scanByte(' ')
	buf := make([]byte, 4096)
	for {
		n, err := wr.Read(buf)
		if err != nil {
			break
		}
		for _, c := range buf[:n] {
			ps.scanByte(c)
		}
	}
	ps.scanByte(' ')

	return ps.tally
}

func decoderForContentType(t string) mahonia.Decoder {
	t = strings.ToLower(t)
	var result mahonia.Decoder

	i := strings.Index(t, "charset=")
	if i != -1 {
		charset := t[i+len("charset="):]
		i = strings.Index(charset, ";")
		if i != -1 {
			charset = charset[:i]
		}
		result = mahonia.NewDecoder(charset)
		if result == nil {
			log.Println("Unknown charset:", charset)
		}
	}

	if result == nil {
		result = mahonia.FallbackDecoder(mahonia.NewDecoder("UTF-8"), mahonia.NewDecoder("windows-1252"))
	}

	if strings.Contains(t, "html") {
		result = mahonia.FallbackDecoder(mahonia.EntityDecoder(), result)
	}

	return result
}
