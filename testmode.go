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

	request := &Request{
		Request: &http.Request{
			Method: "GET",
			URL:    URL,
			Header: make(http.Header),
		},
	}

	filterRequest(request, false)

	if len(request.Tally) == 0 {
		fmt.Println("No URL rules match.")
	} else {
		conf.applyCompoundRules(request.Tally)
		fmt.Println("The following URL rules match:")
		for s, _ := range request.Tally {
			fmt.Println(s)
		}
	}

	if len(request.Scores.data) > 0 {
		fmt.Println()
		fmt.Println("The request has the following category scores:")
		printSortedTally(request.Scores.data)
	}

	if len(request.ACLs.data) > 0 {
		fmt.Println()
		fmt.Println("The request matches the following ACLs:")
		for acl := range request.ACLs.data {
			fmt.Println(acl)
		}
	}

	fmt.Println()
	if request.Action.Action == "" {
		fmt.Println("No ACL rule was triggered.")
	} else {
		fmt.Println("Triggered rule:", request.Action.Action, request.Action.Conditions())
		if len(request.Ignored) > 0 {
			fmt.Println("Ignored categories:", strings.Join(request.Ignored, ", "))
		}
	}

	if conf.changeQuery(URL) {
		fmt.Println()
		fmt.Println("URL modified to:", URL)
	}

	fmt.Println()
	fmt.Println("Downloading content...")
	resp, err := http.DefaultTransport.RoundTrip(request.Request)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()

	fmt.Println(resp.Status)
	fmt.Println()

	respACLs := conf.ACLs.responseACLs(resp)
	acls := unionACLSets(request.ACLs.data, respACLs)

	if len(respACLs) > 0 {
		fmt.Println("The response matches the following ACLs:")
		for acl := range respACLs {
			fmt.Println(acl)
		}
		fmt.Println()
	}

	thisRule, ignored := conf.ChooseACLCategoryAction(acls, request.Scores.data, conf.Threshold, "allow", "block", "block-invisible", "hash-image", "phrase-scan")

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

	tally := make(map[rule]int)
	for k, v := range request.Tally {
		tally[k] = v
	}

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
			conf.applyCompoundRules(tally)
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
				tally[simpleRule{imageHash, h.String()}]++
				fmt.Printf("Matching image hash found: %v (%d bits difference)\n", h, distance)
			}
		}
	}

	scores := conf.categoryScores(tally)

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
