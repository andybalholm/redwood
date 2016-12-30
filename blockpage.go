package main

import (
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

// Functions for displaying block pages.

// transparent1x1 is a single-pixel transparent GIF file.
const transparent1x1 = "GIF89a\x10\x00\x10\x00\x80\xff\x00\xc0\xc0\xc0\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x10\x00\x10\x00\x00\x02\x0e\x84\x8f\xa9\xcb\xed\x0f\xa3\x9c\xb4\u068b\xb3>\x05\x00;"

func (c *config) loadBlockPage(path string) error {
	bt := template.New("blockpage")
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return fmt.Errorf("error loading block page template: %v", err)
	}
	bt.Funcs(template.FuncMap{
		"eq": func(a, b interface{}) bool {
			return a == b
		},
	})
	_, err = bt.Parse(string(content))
	if err != nil {
		return fmt.Errorf("error parsing block page template: %v", err)
	}

	c.BlockTemplate = bt
	return nil
}

type blockData struct {
	URL             string
	Categories      string
	Conditions      string
	User            string
	Tally           string
	Scores          string
	RuleDescription string
	Request         *http.Request
	Response        *http.Response
}

func (c *config) aclDescription(name string) string {
	cat, ok := c.Categories[name]
	if ok {
		return cat.description
	}

	d, ok := c.ACLs.Descriptions[name]
	if ok {
		return d
	}

	return name
}

// showBlockPage shows a block page for a page that was blocked by an ACL.
func (c *config) showBlockPage(w http.ResponseWriter, r *http.Request, resp *http.Response, user string, tally map[rule]int, scores map[string]int, rule ACLActionRule) {
	w.WriteHeader(http.StatusForbidden)
	if c.BlockTemplate == nil {
		return
	}
	data := blockData{
		URL:             r.URL.String(),
		Conditions:      rule.Conditions(),
		User:            user,
		Tally:           listTally(stringTally(tally)),
		Scores:          listTally(scores),
		RuleDescription: rule.Description,
		Request:         r,
		Response:        resp,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Convert rule conditions into category descriptions as much as possible.
	var categories []string
	for _, acl := range rule.Needed {
		categories = append(categories, c.aclDescription(acl))
	}
	for _, acl := range rule.Disallowed {
		categories = append(categories, "not "+c.aclDescription(acl))
	}
	data.Categories = strings.Join(categories, ", ")

	err := c.BlockTemplate.Execute(w, data)
	if err != nil {
		log.Println("Error filling in block page template:", err)
	}
}

// showInvisibleBlock blocks the request with an invisible image.
func showInvisibleBlock(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "image/gif")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprint(w, transparent1x1)
}
