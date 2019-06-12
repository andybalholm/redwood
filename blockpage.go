package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"
)

// Functions for displaying block pages.

// transparent1x1 is a single-pixel transparent GIF file.
const transparent1x1 = "GIF89a\x10\x00\x10\x00\x80\xff\x00\xc0\xc0\xc0\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x10\x00\x10\x00\x00\x02\x0e\x84\x8f\xa9\xcb\xed\x0f\xa3\x9c\xb4\u068b\xb3>\x05\x00;"

func (c *config) loadBlockPage(path string) error {
	if strings.HasPrefix(path, "http") {
		c.BlockTemplate = nil
		c.BlockpageURL = path
		return nil
	}

	bt := template.New("blockpage")
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return fmt.Errorf("error loading block page template: %v", err)
	}
	_, err = bt.Parse(string(content))
	if err != nil {
		return fmt.Errorf("error parsing block page template: %v", err)
	}

	c.BlockTemplate = bt
	c.BlockpageURL = ""
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

// Convert rule conditions into category descriptions as much as possible.
func (c *config) aclDescriptions(rule ACLActionRule) []string {
	var categories []string
	for _, acl := range rule.Needed {
		categories = append(categories, c.aclDescription(acl))
	}
	for _, acl := range rule.Disallowed {
		categories = append(categories, "not "+c.aclDescription(acl))
	}

	return categories
}

// showBlockPage shows a block page for a page that was blocked by an ACL.
func (c *config) showBlockPage(w http.ResponseWriter, r *http.Request, resp *http.Response, user string, tally map[rule]int, scores map[string]int, rule ACLActionRule) {
	switch {
	case c.BlockTemplate != nil:
		data := blockData{
			URL:             r.URL.String(),
			Conditions:      rule.Conditions(),
			User:            user,
			Tally:           listTally(stringTally(tally)),
			Scores:          listTally(scores),
			Categories:      strings.Join(c.aclDescriptions(rule), ", "),
			RuleDescription: rule.Description,
			Request:         r,
			Response:        resp,
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)

		err := c.BlockTemplate.Execute(w, data)
		if err != nil {
			log.Println("Error filling in block page template:", err)
		}

	case c.BlockpageURL != "":
		d := map[string]interface{}{
			"url":            r.URL.String(),
			"rule":           rule,
			"user":           user,
			"tally":          stringTally(tally),
			"scores":         scores,
			"categories":     c.aclDescriptions(rule),
			"method":         r.Method,
			"request-header": r.Header,
		}
		if resp != nil {
			d["response-header"] = resp.Header
		}
		data, err := json.Marshal(d)
		if err != nil {
			log.Println("Error generating JSON info for block page:", err)
			http.Error(w, "", http.StatusForbidden)
			return
		}

		blockResp, err := http.Post(c.BlockpageURL, "application/json", bytes.NewReader(data))
		if err != nil {
			log.Printf("Error fetching blockpage from %s: %v", c.BlockpageURL, err)
			http.Error(w, "", http.StatusForbidden)
			return
		}
		defer blockResp.Body.Close()

		removeHopByHopHeaders(blockResp.Header)
		if blockResp.ContentLength > 0 {
			w.Header().Set("Content-Length", strconv.FormatInt(blockResp.ContentLength, 10))
		}
		blockResp.StatusCode = http.StatusForbidden
		copyResponseHeader(w, blockResp)
		_, err = io.Copy(w, blockResp.Body)
		if err != nil {
			log.Printf("Error copying blockpage: %v", err)
		}

	default:
		http.Error(w, "", http.StatusForbidden)
		return
	}
}

// showInvisibleBlock blocks the request with an invisible image.
func showInvisibleBlock(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "image/gif")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprint(w, transparent1x1)
}
