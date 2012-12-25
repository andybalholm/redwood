package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

// support for running "redwood -test http://example.com"

// runURLTest prints debugging information about how the URL and its content would be rated.
func runURLTest(u string) {
	URL, err := url.Parse(u)
	if err != nil {
		fmt.Println("Could not parse the URL.")
		return
	}

	if URL.Scheme == "" {
		url2, err := url.Parse("http://" + u)
		if err == nil {
			URL = url2
		}
	}

	fmt.Println("URL:", URL)
	fmt.Println()

	sc := scorecard{
		tally: URLRules.MatchingRules(URL),
	}
	sc.calculate("")

	if len(sc.tally) == 0 {
		fmt.Println("No URL rules match.")
	} else {
		fmt.Println("The following URL rules match:")
		for s, _ := range sc.tally {
			fmt.Println(s)
		}
	}

	if len(sc.scores) > 0 {
		fmt.Println()
		fmt.Println("The request has the following category scores:")
		printSortedTally(sc.scores)
	}

	if len(sc.blocked) > 0 {
		fmt.Println()
		fmt.Println("The request is blocked by the following categories:")
		for _, c := range sc.blocked {
			fmt.Println(c)
		}
		fmt.Println()
		fmt.Println("But we'll check the content too anyway.")
	}

	if changeQuery(URL) {
		fmt.Println()
		fmt.Println("URL modified to:", URL)
	}

	fmt.Println()
	fmt.Println("Downloading content...")
	resp, err := http.Get(URL.String())
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()

	fmt.Println()

	contentType, action := checkContentType(resp)
	switch action {
	case ALLOW:
		fmt.Println("The content doesn't seem to be text, so not running a phrase scan.")
		return
	case BLOCK:
		fmt.Println("The content has a banned MIME type:", contentType)
		return
	}

	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error while reading response body:", err)
		return
	}

	modified := false
	charset := findCharset(resp.Header.Get("Content-Type"), content)
	if strings.Contains(contentType, "html") {
		modified = pruneContent(URL, &content, charset)
		charset = "utf-8"
	}
	if modified {
		fmt.Println("Performed content pruning.")
		fmt.Println()
	}

	scanContent(content, contentType, charset, sc.tally)
	sc.calculate("")

	if len(sc.tally) == 0 {
		fmt.Println("No content phrases match.")
	} else {
		fmt.Println("The following rules match:")
		printSortedTally(stringTally(sc.tally))
	}

	if len(sc.scores) > 0 {
		fmt.Println()
		fmt.Println("The response has the following category scores:")
		printSortedTally(sc.scores)
	}

	if len(sc.blocked) > 0 {
		fmt.Println()
		fmt.Println("The page is blocked by the following categories:")
		for _, c := range sc.blocked {
			fmt.Println(c)
		}
	}
}

// printSortedTally prints tally's keys and values in descending order by value.
func printSortedTally(tally map[string]int) {
	for _, rule := range sortedKeys(tally) {
		fmt.Println(rule, tally[rule])
	}
}
