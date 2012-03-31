package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"strings"
)

// Functions for modifying URL query strings

var queryMatcher = newURLMatcher()
var queryChanges = make(map[rule]url.Values)

var queryConfig = newActiveFlag("query-changes", "", "path to config file for modifying URL query strings", loadQueryConfig)

func loadQueryConfig(filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("could not open %s: %s\n", filename, err)
	}
	defer f.Close()
	r := bufio.NewReader(f)

	for {
		line, err := r.ReadString('\n')
		if line == "" {
			if err != io.EOF {
				log.Printf("Error reading %s: %s", filename, err)
			}
			break
		}

		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}

		r, line, err := parseRule(line)
		if err != nil {
			log.Printf("Syntax error in %s: %s", filename, err)
			continue
		}

		if r.t == defaultRule || r.t == contentPhrase {
			log.Printf("Wrong rule type in %s: %s", filename, r)
			continue
		}

		line = strings.TrimSpace(line)
		values, err := url.ParseQuery(line)
		if err != nil {
			log.Printf("Invalid query string %q in %s: %s", line, filename, err)
			continue
		}

		queryMatcher.AddRule(r)
		queryChanges[r] = values
	}

	return nil
}

// changeQuery checks the URL to see if it is a site that is calling for
// query changes. If so, it modifies the URL and returns true.
func (c *context) changeQuery() (changed bool) {
	URL := c.URL()

	matches := queryMatcher.MatchingRules(URL)
	if len(matches) == 0 {
		return false
	}

	values := URL.Query()

	for urlRule := range matches {
		newValues := queryChanges[urlRule]
		for k, v := range newValues {
			values[k] = v
		}
	}

	URL.RawQuery = values.Encode()
	return true
}
