package main

import (
	"fmt"
	"http"
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
}
