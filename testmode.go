package main

import (
	"fmt"
	"http"
	"mahonia.googlecode.com/hg"
)

// support for running "redwood -test http://example.com"

// runURLTest prints debugging information about how the URL and its content would be rated.
func runURLTest(u string) {
	url, err := http.ParseURL(u)
	if err != nil {
		fmt.Println("Could not parse the URL.")
		return
	}

	fmt.Println("URL:", url)
	fmt.Println()

	matches := URLRules.MatchingRules(url)
	if len(matches) == 0 {
		fmt.Println("No URL rules match.")
	} else {
		fmt.Println("The following URL rules match:")
		for _, s := range matches {
			fmt.Println(s)
		}
	}

	fmt.Println()
	fmt.Println("Downloading content...")
	res, err := http.Get(u)
	if err != nil {
		fmt.Println(err)
		return
	}

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

	fmt.Println()

	if len(ps.tally) == 0 {
		fmt.Println("No content phrases match.")
	} else {
		fmt.Println("The following content phrases match:")
		for rule, count := range ps.tally {
			fmt.Println(rule, count)
		}
	}
}
