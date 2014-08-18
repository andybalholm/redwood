package main

import (
	"bytes"
	"io"
	"log"
	"mime"
	"net/http"
	"strings"
)

// Filtering by MIME type.

// We use the action type from categories.go, but instead of BLOCK, IGNORE, and
// ALLOW, here it is BLOCK, FILTER, and ALLOW.
const FILTER = IGNORE

// checkContentType examines the request's Content-Type header, and potentially
// its content as well, to determine the content's MIME type.
// Then it decides, based on the MIME type, whether it should be allowed,
// filtered, or blocked.
func (c *config) checkContentType(resp *http.Response) (contentType string, a action) {
	ct, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || !strings.Contains(ct, "/") {
		ct = ""
	}

	switch resp.Header.Get("Content-Encoding") {
	case "", "gzip", "deflate":
		// This is an encoding we can understand.

	case "GZIP":
		resp.Header.Set("Content-Encoding", "gzip")

	case "utf-8", "UTF-8", "none":
		// This is an error.
		resp.Header.Set("Content-Encoding", "")

	default:
		// If the server is using a Content-Encoding that we don't understand,
		// we can't decode the content to filter it.
		log.Println("unknown Content-Encoding", resp.Header.Get("Content-Encoding"), "for", resp.Request.URL)
		return ct, ALLOW
	}

	switch ct {
	case "unknown/unknown", "application/unknown", "*/*", "", "application/octet-stream":
		if resp.Header.Get("Content-Encoding") == "" {
			// These types tend to be used for content whose type is unknown,
			// so we should try to second-guess them.
			// But we don't bother if the content is gzipped; then we'd get application/gzip.
			// We can hope (probably in vain) that a server smart enough to compress the
			// content is smart enough to give us a correct media type.
			preview := make([]byte, 512)
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
	}

	if a, ok := c.MIMEActions[ct]; ok {
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
