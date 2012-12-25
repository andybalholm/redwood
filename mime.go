package main

import (
	"bytes"
	"io"
	"mime"
	"net/http"
	"strings"
)

// Filtering by MIME type.

// The action to take for files of each type.
// If it is not specified here, types beginning with "text" will be
// content-filtered, and others will be allowed without scanning the content.
var mimeActions = map[string]action{}

// We use the action type from categories.go, but instead of BLOCK, IGNORE, and
// ALLOW, here it is BLOCK, FILTER, and ALLOW.
const FILTER = IGNORE

var mimeAllow = newActiveFlag("mime-allow", "", "content type to allow without phrase scan",
	func(t string) error {
		mimeActions[t] = ALLOW
		return nil
	})

var mimeFilter = newActiveFlag("mime-filter", "", "content type to filter",
	func(t string) error {
		mimeActions[t] = FILTER
		return nil
	})

var mimeBlock = newActiveFlag("mime-block", "", "content type to block",
	func(t string) error {
		mimeActions[t] = BLOCK
		return nil
	})

// checkContentType examines the request's Content-Type header, and potentially
// its content as well, to determine the content's MIME type.
// Then it decides, based on the MIME type, whether it should be allowed,
// filtered, or blocked.
func checkContentType(resp *http.Response) (contentType string, a action) {
	ct, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || !strings.Contains(ct, "/") {
		ct = ""
	}

	switch ct {
	case "text/plain", "text/html", "unknown/unknown", "application/unknown", "*/*", "", "application/octet-stream":
		// These types tend to be used for content whose type is unknown,
		// so we should try to second-guess them.
		preview := make([]byte, 1024)
		n, _ := resp.Body.Read(preview)
		preview = preview[:n]

		if n > 0 {
			ct, _, _ = mime.ParseMediaType(http.DetectContentType(preview))

			// Make the preview data available for re-reading.
			var rc struct {
				io.Reader
				io.Closer
			}
			rc.Reader = io.MultiReader(bytes.NewBuffer(preview), resp.Body)
			rc.Closer = resp.Body
			resp.Body = rc
		}
	}

	if a, ok := mimeActions[ct]; ok {
		return ct, a
	}
	if strings.HasPrefix(ct, "text/") {
		return ct, FILTER
	}
	return ct, ALLOW
}

// baseType strips off any modifiers (such as charset) and returns the simple
// MIME type.
func baseType(t string) string {
	if semicolon := strings.Index(t, ";"); semicolon != -1 {
		t = t[:semicolon]
	}
	return strings.TrimSpace(t)
}
