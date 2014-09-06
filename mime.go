package main

import (
	"bytes"
	"io"
	"mime"
	"net/http"
	"strings"
)

// fixContentType checks resp's Content-Type header. If it is missing or too
// general, it sniffs the body content to find the content type, and updates
// the Content-Type header.
func fixContentType(resp *http.Response) {
	ct, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || !strings.Contains(ct, "/") {
		ct = ""
	}

	switch ct {
	case "unknown/unknown", "application/unknown", "*/*", "", "application/octet-stream":
		// These types tend to be used for content whose type is unknown,
		// so we should try to second-guess them.
		preview := make([]byte, 512)
		n, _ := resp.Body.Read(preview)
		preview = preview[:n]

		if n > 0 {
			ct, _, _ = mime.ParseMediaType(http.DetectContentType(preview))
			if ct != "application/octet-stream" {
				resp.Header.Set("Content-Type", ct)
			}

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
