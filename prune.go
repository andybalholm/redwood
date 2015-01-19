package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"

	"code.google.com/p/cascadia"
	"golang.org/x/net/html"
	"golang.org/x/net/html/charset"
	"golang.org/x/text/transform"
)

// Functions for content pruning (removing specific HTML elements from the page)

var metaCharsetSelector = cascadia.MustCompile(`meta[charset], meta[http-equiv="Content-Type"]`)

// A filteredPruningRule represents an HTML element that should be removed from
// the page if its score in a blocked category exceeds Threshold.
type filteredPruningRule struct {
	Threshold int
	Selector  cascadia.Selector
}

func (c *config) loadPruningConfig(filename string) error {
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

		// See if there is a threshold value between the rule and the selector.
		threshold := 0
		line = strings.TrimSpace(line)
		if space := strings.Index(line, " "); space != -1 {
			if t, err := strconv.Atoi(line[:space]); err == nil {
				threshold = t
				line = line[space+1:]
			}
		}

		sel, err := cascadia.Compile(line)
		if err != nil {
			log.Printf("Invalid CSS selector %q in %s: %s", line, filename, err)
			continue
		}

		c.PruneMatcher.AddRule(r)

		if threshold == 0 {
			if oldAction, ok := c.PruneActions[r]; ok {
				c.PruneActions[r] = func(n *html.Node) bool {
					return oldAction(n) || sel(n)
				}
			} else {
				c.PruneActions[r] = sel
			}
		} else {
			c.FilteredPruning[r] = append(c.FilteredPruning[r], filteredPruningRule{threshold, sel})
		}
	}

	return nil
}

// pruneContent checks the URL to see if it is a site that is calling for
// content pruning. If so, it parses the HTML, removes the specified tags, and
// re-renders the HTML. It returns true if the content was changed.
func (c *config) pruneContent(URL *url.URL, content *[]byte, cs string, acls map[string]bool) bool {
	URLMatches := c.PruneMatcher.MatchingRules(URL)
	if len(URLMatches) == 0 {
		return false
	}

	var r io.Reader = bytes.NewReader(*content)

	if cs != "utf-8" {
		e, _ := charset.Lookup(cs)
		r = transform.NewReader(r, e.NewDecoder())
	}

	tree, err := html.Parse(r)
	if err != nil {
		log.Printf("Error parsing html from %s: %s", URL, err)
		return false
	}

	modified := false
	for urlRule := range URLMatches {
		sel, ok := c.PruneActions[urlRule]
		if ok && prune(tree, sel) > 0 {
			modified = true
		}
		for _, fpr := range c.FilteredPruning[urlRule] {
			if c.pruneFiltered(tree, fpr, acls) > 0 {
				modified = true
			}
		}
	}

	if !modified {
		return false
	}

	// Mark the new content as having a charset of UTF-8.
	prune(tree, metaCharsetSelector)

	b := new(bytes.Buffer)
	err = html.Render(b, tree)
	if err != nil {
		log.Printf("Error rendering modified content from %s: %s", URL, err)
		return false
	}

	*content = b.Bytes()
	return true
}

// prune deletes children of n that match sel, and returns how many were
// deleted.
func prune(n *html.Node, sel cascadia.Selector) int {
	count := 0
	child := n.FirstChild
	for child != nil {
		if sel(child) {
			nextChild := child.NextSibling
			n.RemoveChild(child)
			child = nextChild
			count++
		} else {
			count += prune(child, sel)
			child = child.NextSibling
		}
	}
	return count
}

// pruneFiltered phrase-scans children of n that match fpr.Selector, deletes
// those that should be removed according to fpr.Threshold and acls, and
// returns how many were deleted.
func (c *config) pruneFiltered(n *html.Node, fpr filteredPruningRule, acls map[string]bool) int {
	count := 0
	child := n.FirstChild
	for child != nil {
		remove := false
		if fpr.Selector(child) {
			buf := new(bytes.Buffer)
			html.Render(buf, child)
			tally := make(map[rule]int)
			c.scanContent(buf.Bytes(), "text/html", "utf-8", tally)
			scores := c.categoryScores(tally)
			categories := significantCategories(scores, fpr.Threshold)
			rule := c.ChooseACLCategoryAction(acls, categories, "allow", "block", "block-invisible")
			remove = rule.Action == "block" || rule.Action == "block-invisible"
		}

		if remove {
			nextChild := child.NextSibling
			n.RemoveChild(child)
			child = nextChild
			count++
		} else {
			count += c.pruneFiltered(child, fpr, acls)
			child = child.NextSibling
		}
	}

	return count
}
