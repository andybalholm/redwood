package main

import (
	"code.google.com/p/go-icap"
	"fmt"
	"net/http"
	"net/url"
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

	c := context{
		req: &icap.Request{
			Request: &http.Request{
				URL: URL,
			},
		},
	}

	fmt.Println("URL:", URL)
	fmt.Println()

	c.scanURL()

	if len(c.tally) == 0 {
		fmt.Println("No URL rules match.")
	} else {
		fmt.Println("The following URL rules match:")
		for s, _ := range c.tally {
			fmt.Println(s)
		}
	}

	if len(c.scores) > 0 {
		fmt.Println()
		fmt.Println("The request has the following category scores:")
		printSortedTally(c.scores)
	}

	if len(c.blocked) > 0 {
		fmt.Println()
		fmt.Println("The request is blocked by the following categories:")
		for _, c := range c.blocked {
			fmt.Println(c)
		}
		return
	}

	fmt.Println()
	fmt.Println("Downloading content...")
	res, err := http.Get(URL.String())
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println()
	c.req.Response = res
	c.content = responseContent(res)

	c.checkContentType()
	switch c.action {
	case ALLOW:
		fmt.Println("The content doesn't seem to be text, so not running a phrase scan.")
		return
	case BLOCK:
		fmt.Println("The content has a banned MIME type:", c.mime)
		return
	}

	c.pruneContent()
	if c.modified {
		fmt.Println("Performed phrase pruning.")
		fmt.Println()
	}

	c.scanContent()

	if len(c.tally) == 0 {
		fmt.Println("No content phrases match.")
	} else {
		fmt.Println("The following rules match:")
		printSortedTally(c.stringTally())
	}

	if len(c.scores) > 0 {
		fmt.Println()
		fmt.Println("The response has the following category scores:")
		printSortedTally(c.scores)
	}

	if len(c.blocked) > 0 {
		fmt.Println()
		fmt.Println("The page is blocked by the following categories:")
		for _, c := range c.blocked {
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
