package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

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
	categories := conf.significantCategories(scores)

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

	rule := conf.ChooseACLCategoryAction(reqACLs, categories, "allow", "block", "block-invisible")
	fmt.Println()
	if rule.Action == "" {
		fmt.Println("No ACL rule was triggered.")
	} else {
		fmt.Println("Triggered rule:", rule.Action, rule.Conditions())
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

	fixContentType(resp)
	respACLs := conf.ACLs.responseACLs(resp)
	acls := unionACLSets(reqACLs, respACLs)

	if len(respACLs) > 0 {
		fmt.Println("The response matches the following ACLs:")
		for acl := range respACLs {
			fmt.Println(acl)
		}
		fmt.Println()
	}

	rule = conf.ChooseACLCategoryAction(acls, categories, "allow", "block", "block-invisible", "phrase-scan")

	if rule.Action == "" {
		fmt.Println("No ACL rule was triggered.")
	} else {
		fmt.Println("Triggered rule:", rule.Action, rule.Conditions())
	}

	if rule.Action != "phrase-scan" {
		return
	}
	fmt.Println()

	contentType := resp.Header.Get("Content-Type")

	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error while reading response body:", err)
		return
	}

	modified := false
	_, cs, _ := charset.DetermineEncoding(content, resp.Header.Get("Content-Type"))
	if strings.Contains(contentType, "html") {
		modified = conf.pruneContent(URL, &content, cs, acls)
	}
	if modified {
		cs = "utf-8"
		fmt.Println("Performed content pruning.")
		fmt.Println()
	}

	conf.scanContent(content, contentType, cs, tally)
	scores = conf.categoryScores(tally)
	categories = conf.significantCategories(scores)

	if len(tally) == 0 {
		fmt.Println("No content phrases match.")
	} else {
		fmt.Println("The following rules match:")
		printSortedTally(stringTally(tally))
	}

	if len(scores) > 0 {
		fmt.Println()
		fmt.Println("The response has the following category scores:")
		printSortedTally(scores)
	}
	fmt.Println()

	rule = conf.ChooseACLCategoryAction(acls, categories, "allow", "block", "block-invisible")

	if rule.Action == "" {
		fmt.Println("No ACL rule was triggered.")
	} else {
		fmt.Println("Triggered rule:", rule.Action, rule.Conditions())
	}
}

// printSortedTally prints tally's keys and values in descending order by value.
func printSortedTally(tally map[string]int) {
	for _, rule := range sortedKeys(tally) {
		fmt.Println(rule, tally[rule])
	}
}
