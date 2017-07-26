package main

import (
	"bytes"
	"fmt"
	"image"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/andybalholm/dhash"
	"golang.org/x/net/html"
	"golang.org/x/net/html/charset"
)

// support for running "redwood -test http://example.com"

// runURLTest prints debugging information about how the URL and its content would be rated.
func runURLTest(u string) {
	conf := getConfig()

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

	tally := conf.URLRules.MatchingRules(URL)
	scores := conf.categoryScores(tally)

	if len(tally) == 0 {
		fmt.Println("No URL rules match.")
	} else {
		fmt.Println("The following URL rules match:")
		for s, _ := range tally {
			fmt.Println(s)
		}
	}

	if len(scores) > 0 {
		fmt.Println()
		fmt.Println("The request has the following category scores:")
		printSortedTally(scores)
	}

	req := &http.Request{
		Method: "GET",
		URL:    URL,
		Header: make(http.Header),
	}
	reqACLs := conf.ACLs.requestACLs(req, "")
	if len(reqACLs) > 0 {
		fmt.Println()
		fmt.Println("The request matches the following ACLs:")
		for acl := range reqACLs {
			fmt.Println(acl)
		}
	}

	thisRule, ignored := conf.ChooseACLCategoryAction(reqACLs, scores, conf.Threshold, "allow", "block", "block-invisible")
	fmt.Println()
	if thisRule.Action == "" {
		fmt.Println("No ACL rule was triggered.")
	} else {
		fmt.Println("Triggered rule:", thisRule.Action, thisRule.Conditions())
		if len(ignored) > 0 {
			fmt.Println("Ignored categories:", strings.Join(ignored, ", "))
		}
	}

	if conf.changeQuery(URL) {
		fmt.Println()
		fmt.Println("URL modified to:", URL)
	}

	fmt.Println()
	fmt.Println("Downloading content...")
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()

	fmt.Println(resp.Status)
	fmt.Println()

	respACLs := conf.ACLs.responseACLs(resp)
	acls := unionACLSets(reqACLs, respACLs)

	if len(respACLs) > 0 {
		fmt.Println("The response matches the following ACLs:")
		for acl := range respACLs {
			fmt.Println(acl)
		}
		fmt.Println()
	}

	thisRule, ignored = conf.ChooseACLCategoryAction(acls, scores, conf.Threshold, "allow", "block", "block-invisible", "hash-image", "phrase-scan")

	if thisRule.Action == "" {
		fmt.Println("No ACL rule was triggered.")
	} else {
		fmt.Println("Triggered rule:", thisRule.Action, thisRule.Conditions())
		if len(ignored) > 0 {
			fmt.Println("Ignored categories:", strings.Join(ignored, ", "))
		}
	}

	if thisRule.Action != "phrase-scan" && thisRule.Action != "hash-image" {
		return
	}
	fmt.Println()

	contentType := resp.Header.Get("Content-Type")

	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error while reading response body:", err)
		return
	}

	var doc *html.Node
	switch thisRule.Action {
	case "phrase-scan":
		modified := false
		_, cs, _ := charset.DetermineEncoding(content, resp.Header.Get("Content-Type"))
		if strings.Contains(contentType, "html") {
			modified = conf.pruneContent(URL, &content, cs, &doc)
		}
		if modified {
			cs = "utf-8"
			fmt.Println("Performed content pruning.")
			fmt.Println()
		}

		conf.scanContent(content, contentType, cs, tally)
		if len(tally) == 0 {
			fmt.Println("No content phrases match.")
		} else {
			fmt.Println("The following rules match:")
			printSortedTally(stringTally(tally))
		}

	case "hash-image":
		img, _, err := image.Decode(bytes.NewReader(content))
		if err != nil {
			fmt.Printf("Error decoding image: %v\n", err)
			return
		}
		hash := dhash.New(img)
		fmt.Println("The image's hash is", hash)

		for _, h := range conf.ImageHashes {
			distance := dhash.Distance(hash, h.Hash)
			if distance <= h.Threshold || h.Threshold == -1 && distance <= conf.DhashThreshold {
				tally[rule{imageHash, h.String()}]++
				fmt.Printf("Matching image hash found: %v (%d bits difference)\n", h, distance)
			}
		}
	}

	scores = conf.categoryScores(tally)

	if len(scores) > 0 {
		fmt.Println()
		fmt.Println("The response has the following category scores:")
		printSortedTally(scores)
	}
	fmt.Println()

	thisRule, ignored = conf.ChooseACLCategoryAction(acls, scores, conf.Threshold, "allow", "block", "block-invisible")

	if thisRule.Action == "" {
		fmt.Println("No ACL rule was triggered.")
	} else {
		fmt.Println("Triggered rule:", thisRule.Action, thisRule.Conditions())
		if len(ignored) > 0 {
			fmt.Println("Ignored categories:", strings.Join(ignored, ", "))
		}
	}
}

// printSortedTally prints tally's keys and values in descending order by value.
func printSortedTally(tally map[string]int) {
	for _, rule := range sortedKeys(tally) {
		fmt.Println(rule, tally[rule])
	}
}
