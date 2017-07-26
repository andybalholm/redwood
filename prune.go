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

	"github.com/andybalholm/cascadia"
	"golang.org/x/net/html"
	"golang.org/x/net/html/charset"
	"golang.org/x/text/transform"
)

// Functions for content pruning (removing specific HTML elements from the page)

var metaCharsetSelector selector

func init() {
	var err error
	metaCharsetSelector, err = newSelector(`meta[charset], meta[http-equiv="Content-Type"]`)
	if err != nil {
		panic(err)
	}
}

// A filteredPruningRule represents an HTML element that should be removed from
// the page if its score in a blocked category exceeds Threshold.
type filteredPruningRule struct {
	Threshold int
	Selector  selector
}

// A selector is a CSS selector that remembers the original text it was parsed
// from.
type selector struct {
	cascadia.Selector
	s string
}

func newSelector(s string) (selector, error) {
	cs, err := cascadia.Compile(s)
	if err != nil {
		return selector{}, err
	}
	return selector{
		Selector: cs,
		s:        s,
	}, nil
}

func (s selector) String() string {
	return s.s
}

// combineSelectors returns a selector that will match wherever a or b matches.
func combineSelectors(a, b selector) selector {
	s := selector{
		Selector: func(n *html.Node) bool { return a.Selector(n) || b.Selector(n) },
		s:        a.s + ", " + b.s,
	}
	// :contains selectors don't work in browser CSS, just in jQuery and Cascadia.
	// So leave those out of the string version.
	if strings.Contains(a.s, ":contains") {
		s.s = b.s
	} else if strings.Contains(b.s, ":contains") {
		s.s = a.s
	}
	return s
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

		sel, err := newSelector(line)
		if err != nil {
			log.Printf("Invalid CSS selector %q in %s: %s", line, filename, err)
			continue
		}

		if threshold == 0 {
			if oldAction, ok := c.PruneActions[r]; ok {
				c.PruneActions[r] = combineSelectors(oldAction, sel)
			} else {
				c.PruneActions[r] = sel
			}
			c.PruneMatcher.AddRule(r)
		} else {
			c.FilteredPruning[r] = append(c.FilteredPruning[r], filteredPruningRule{threshold, sel})
			c.FilteredPruneMatcher.AddRule(r)
		}
	}

	return nil
}

func parseHTML(content []byte, cs string) (*html.Node, error) {
	var r io.Reader = bytes.NewReader(content)

	if cs != "utf-8" {
		e, _ := charset.Lookup(cs)
		r = transform.NewReader(r, e.NewDecoder())
	}

	return html.Parse(r)
}

var headSelector = cascadia.MustCompile("head")

// pruneContent checks the URL to see if it is a site that is calling for
// content pruning. If so, it parses the HTML, removes the specified tags, and
// re-renders the HTML. It returns true if the content was changed. The content
// may be pre-parsed and passed in as tree; the final parse tree will be stored
// in tree.
func (c *config) pruneContent(URL *url.URL, content *[]byte, cs string, tree **html.Node) bool {
	URLMatches := c.PruneMatcher.MatchingRules(URL)
	if len(URLMatches) == 0 {
		return false
	}

	if *tree == nil {
		doc, err := parseHTML(*content, cs)
		if err != nil {
			log.Printf("Error parsing html from %s: %s", URL, err)
			return false
		}
		*tree = doc
	}

	toDelete := map[*html.Node]bool{}
	var selectors []selector

	for urlRule := range URLMatches {
		if sel, ok := c.PruneActions[urlRule]; ok {
			prune(*tree, sel, toDelete)
			selectors = append(selectors, sel)
		}
	}

	if len(toDelete) == 0 {
		return false
	}

	// Remove any meta tag that indicated the charset, since it will be
	// re-rendered as UTF-8.
	prune(*tree, metaCharsetSelector, toDelete)

	// Actually delete the nodes that are to be removed.
	for n := range toDelete {
		n.Parent.RemoveChild(n)
	}

	// Add a style element to hide nodes that match the pruned selectors, in case they
	// get added by Ajax.
	css := new(bytes.Buffer)
	for _, sel := range selectors {
		fmt.Fprintf(css, "%s { display: none !important }\n", sel)
	}
	style := &html.Node{
		Type: html.ElementNode,
		Data: "style",
	}
	style.AppendChild(&html.Node{
		Type: html.TextNode,
		Data: string(css.Bytes()),
	})
	head := headSelector.MatchFirst(*tree)
	if head != nil {
		head.AppendChild(style)
	}

	b := new(bytes.Buffer)
	err := html.Render(b, *tree)
	if err != nil {
		log.Printf("Error rendering modified content from %s: %s", URL, err)
		return false
	}

	*content = b.Bytes()
	return true
}

func (c *config) doFilteredPruning(URL *url.URL, content []byte, cs string, acls map[string]bool, tree **html.Node) bool {
	URLMatches := c.FilteredPruneMatcher.MatchingRules(URL)
	if len(URLMatches) == 0 {
		return false
	}

	if *tree == nil {
		doc, err := parseHTML(content, cs)
		if err != nil {
			log.Printf("Error parsing html from %s: %s", URL, err)
			return false
		}
		*tree = doc
	}

	toDelete := map[*html.Node]bool{}

	for urlRule := range URLMatches {
		for _, fpr := range c.FilteredPruning[urlRule] {
			c.pruneFiltered(*tree, fpr, acls, toDelete)
		}
	}

	if len(toDelete) == 0 {
		return false
	}

	// Mark the new content as having a charset of UTF-8.
	prune(*tree, metaCharsetSelector, toDelete)

	// Actually delete the nodes that are to be removed.
	for n := range toDelete {
		n.Parent.RemoveChild(n)
	}

	return true
}

// prune finds children of n that match sel, and adds them to toDelete.
func prune(n *html.Node, sel selector, toDelete map[*html.Node]bool) {
	for child := n.FirstChild; child != nil; child = child.NextSibling {
		switch {
		case toDelete[child]:
			// Ignore it.
		case sel.Selector(child):
			toDelete[child] = true
		default:
			prune(child, sel, toDelete)
		}
	}
}

// pruneFiltered phrase-scans children of n that match fpr.Selector, and adds
// to toDelete those that should be removed according to fpr.Threshold and acls.
func (c *config) pruneFiltered(n *html.Node, fpr filteredPruningRule, acls map[string]bool, toDelete map[*html.Node]bool) {
	for child := n.FirstChild; child != nil; child = child.NextSibling {
		if toDelete[child] {
			continue
		}

		remove := false
		if fpr.Selector.Selector(child) {
			buf := new(bytes.Buffer)
			html.Render(buf, child)
			tally := make(map[rule]int)
			c.scanContent(buf.Bytes(), "text/html", "utf-8", tally)
			scores := c.categoryScores(tally)
			rule, _ := c.ChooseACLCategoryAction(acls, scores, fpr.Threshold, "allow", "block", "block-invisible")
			remove = rule.Action == "block" || rule.Action == "block-invisible"
		}

		if remove {
			toDelete[child] = true
		} else {
			c.pruneFiltered(child, fpr, acls, toDelete)
		}
	}
}
