package main

import (
	"bytes"
	"exp/html"
	"mime"
	"strings"
	"unicode/utf8"
)

// Character-set detection.

func (c *context) findCharset() {
	c.charset = findCharset(c.contentType(), c.content)
}

// findCharset returns the character encoding to be used to interpret the
// page's content.
func findCharset(declaredContentType string, content []byte) (charset string) {
	defer func() {
		if ce := compatibilityEncodings[charset]; ce != "" {
			charset = ce
		}
	}()

	cs := charsetFromContentType(declaredContentType)
	if cs != "" {
		return cs
	}

	if len(content) > 1024 {
		content = content[:1024]
	}

	if len(content) >= 2 {
		if content[0] == 0xfe && content[1] == 0xff {
			return "utf-16be"
		}
		if content[0] == 0xff && content[1] == 0xfe {
			return "utf-16le"
		}
	}

	if len(content) >= 3 && content[0] == 0xef && content[1] == 0xbb && content[2] == 0xbf {
		return "utf-8"
	}

	if strings.Contains(declaredContentType, "html") || declaredContentType == "" {
		// Look for a <meta> tag giving the encoding.
		tree, err := html.Parse(bytes.NewBuffer(content))
		if err == nil {
			for _, n := range metaCharsetSelector.MatchAll(tree) {
				a := make(map[string]string)
				for _, attr := range n.Attr {
					a[attr.Key] = attr.Val
				}
				if charsetAttr := a["charset"]; charsetAttr != "" {
					return strings.ToLower(charsetAttr)
				}
				if strings.EqualFold(a["http-equiv"], "Content-Type") {
					cs = charsetFromContentType(a["content"])
					if cs != "" {
						return cs
					}
				}
			}
		}
	}

	// Try to detect UTF-8.
	// First eliminate any partial rune that may be split by the 1024-byte boundary.
	for i := len(content) - 1; i >= 0 && i > len(content)-4; i-- {
		b := content[i]
		if b < 128 {
			break
		}
		if utf8.RuneStart(b) {
			content = content[:i]
			break
		}
	}
	if utf8.Valid(content) {
		return "utf-8"
	}

	return "windows-1252"
}

func charsetFromContentType(t string) string {
	t = strings.ToLower(t)
	_, params, _ := mime.ParseMediaType(t)
	return params["charset"]
}

// compatibilityEncodings contains character sets that should be misinterpreted
// for compatibility. The encodings that are commented out are not yet
// implemented by the Mahonia library.
var compatibilityEncodings = map[string]string{
	//	"euc-kr":         "windows-949",
	//	"euc-jp":         "cp51932",
	"gb2312":     "gbk",
	"gb_2312-80": "gbk",
	//	"iso-2022-jp":    "cp50220",
	"iso-8859-1":  "windows-1252",
	"iso-8859-9":  "windows-1254",
	"iso-8859-11": "windows-874",
	//	"ks_c_5601-1987": "windows-949",
	//	"shift_jis":      "windows-31j",
	"tis-620":  "windows-874",
	"us-ascii": "windows-1252",
}
