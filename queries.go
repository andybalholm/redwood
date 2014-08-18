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

func (c *config) loadQueryConfig(filename string) error {
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

		c.QueryMatcher.AddRule(r)
		if changes, ok := c.QueryChanges[r]; ok {
			// Merge the new values into the old ones.
			for k, v := range values {
				changes[k] = v
			}
			c.QueryChanges[r] = changes
		} else {
			c.QueryChanges[r] = values
		}
	}

	return nil
}

// changeQuery checks the URL to see if it is a site that is calling for
// query changes. If so, it modifies the URL and returns true.
func (c *config) changeQuery(URL *url.URL) (changed bool) {
	matches := c.QueryMatcher.MatchingRules(URL)
	if len(matches) == 0 {
		return false
	}

	values := URL.Query()

	for urlRule := range matches {
		newValues := c.QueryChanges[urlRule]
		for k, v := range newValues {
			values[k] = v
		}
	}

	URL.RawQuery = values.Encode()
	return true
}
