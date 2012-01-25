package main

import (
	"code.google.com/p/go-icap"
	"net/http"
	"net/url"
)

// A context stores all kinds of information about a page that is being
// filtered in one place.
type context struct {
	req *icap.Request // the ICAP request that we're dealing with

	content     []byte         // the content of the page
	charset     string         // the page's character encoding
	modified    bool           // whether the content was modified
	tally       map[rule]int   // count of matches for each rule
	scores      map[string]int // score for each category
	blocked     []string       // categories that cause the page to be blocked
	action      action         // action to take for the page
}

func (c *context) URL() *url.URL {
	return c.req.Request.URL
}

func (c *context) httpRequest() *http.Request {
	return c.req.Request
}

func (c *context) httpResponse() *http.Response {
	return c.req.Response
}

func (c *context) user() string {
	u := c.req.Header.Get("X-Client-Username")
	if u != "" {
		return u
	}
	return c.req.Header.Get("X-Client-IP")
}

func (c *context) contentType() string {
	if c.req.Response == nil {
		return ""
	}
	return c.req.Response.Header.Get("Content-Type")
}
