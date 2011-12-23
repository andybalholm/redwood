package main

import (
	"net/http"
	"net/url"
)

// A context stores all kinds of information about a page that is being
// filtered in one place.
type context struct {
	URL         *url.URL       // the page's URL
	resp        *http.Response // the response received when fetching the page
	user        string         // the IP address or user name of the client
	content     []byte         // the content of the page
	contentType string         // the page's MIME type as declared
	tally       map[string]int // count of matches for each rule
	scores      map[string]int // score for each category
	blocked     []string       // categories that cause the page to be blocked
	action      action         // action to take for the page
}
