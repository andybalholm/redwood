package main

// scanning an HTTP response for phrases

import (
	"http"
	"mahonia.googlecode.com/hg"
)

// phrasesInResponse scans the content of an http.Response for phrases,
// and returns a map of phrases and counts.
func phrasesInResponse(res *http.Response) map[string]int {
	defer res.Body.Close()
	wr := newWordReader(res.Body, mahonia.NewDecoder("UTF-8"))
	ps := newPhraseScanner()
	ps.scanByte(' ')
	buf := make([]byte, 4096)
	for {
		n, err := wr.Read(buf)
		if err != nil {
			break
		}
		for i := 0; i < n; i++ {
			ps.scanByte(buf[i])
		}
	}
	ps.scanByte(' ')

	return ps.tally
}
