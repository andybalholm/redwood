package main

import (
	"code.google.com/p/go-icap"
	"net/http"
	"net/url"
)

// A context stores all kinds of information about a page that is being
// filtered in one place.
type context struct {
	icapRequest *icap.Request
	request     *http.Request
	response    *http.Response

	content  []byte // the content of the page
	mime     string // the MIME type of the content, after sniffing
	charset  string // the page's character encoding
	modified bool   // whether the content was modified
	scorecard
}

func (c *context) URL() *url.URL {
	return c.request.URL
}

func (c *context) user() string {
	u := c.icapRequest.Header.Get("X-Client-Username")
	if u != "" {
		return u
	}
	return c.icapRequest.Header.Get("X-Client-IP")
}

func (c *context) contentType() string {
	if c.response == nil {
		return ""
	}
	return c.response.Header.Get("Content-Type")
}
