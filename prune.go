package main

import (
	"bufio"
	"bytes"
	"code.google.com/p/cascadia"
	"code.google.com/p/mahonia"
	"exp/html"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

// Functions for content pruning (removing specific HTML elements from the page)

var pruneMatcher = newURLMatcher()
var pruneActions = make(map[rule]cascadia.Selector)

var pruneConfig = newActiveFlag("content-pruning", "", "path to config file for content pruning", loadPruningConfig)

var metaCharsetSelector = cascadia.MustCompile(`meta[charset], meta[http-equiv="Content-Type"]`)

func loadPruningConfig(filename string) error {
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

		sel, err := cascadia.Compile(line)
		if err != nil {
			log.Printf("Invalid CSS selector %q in %s: %s", line, filename, err)
			continue
		}

		pruneMatcher.AddRule(r)
		pruneActions[r] = sel
	}

	return nil
}

// pruneContent checks the URL to see if it is a site that is calling for
// content pruning. If so, it parses the HTML, removes the specified tags, and
// re-renders the HTML.
func (c *context) pruneContent() {
	if !strings.Contains(c.contentType(), "html") {
		return
	}
	URLMatches := pruneMatcher.MatchingRules(c.URL())
	if len(URLMatches) == 0 {
		return
	}

	var r io.Reader = bytes.NewBuffer(c.content)
	if c.charset == "" {
		c.findCharset()
	}

	if c.charset != "utf-8" {
		d := mahonia.NewDecoder(c.charset)
		if d == nil {
			log.Printf("Unsupported charset (%s) on %s", c.charset, c.URL())
		} else {
			r = d.NewReader(r)
		}
	}

	tree, err := html.Parse(r)
	if err != nil {
		log.Printf("Error parsing html from %s: %s", c.URL(), err)
		return
	}

	for urlRule := range URLMatches {
		sel := pruneActions[urlRule]
		if prune(tree, sel) > 0 {
			c.modified = true
		}
	}

	if !c.modified {
		return
	}

	// Mark the new content as having a charset of UTF-8.
	prune(tree, metaCharsetSelector)
	c.httpResponse().Header.Set("Content-Type", "text/html; charset=utf-8")

	b := new(bytes.Buffer)
	err = html.Render(b, tree)
	if err != nil {
		log.Printf("Error rendering modified content from %s: %s", c.URL(), err)
		return
	}

	c.content = b.Bytes()
}

// prune deletes children of n that match sel, and returns how many were
// deleted.
func prune(n *html.Node, sel cascadia.Selector) int {
	count := 0
	for i := len(n.Child) - 1; i >= 0; i-- {
		child := n.Child[i]
		if sel(child) {
			n.Remove(child)
			count++
		} else {
			count += prune(child, sel)
		}
	}
	return count
}
