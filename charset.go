package main

import (
	"bytes"
	"html"
	"strings"
	"unicode/utf8"
)

// Character-set detection.

// findCharset determines the character encoding to be used to interpret the
// page's content, and stores it in c.charset.
func (c *context) findCharset() {
	cs := charsetFromContentType(c.contentType)
	content := c.content
	if len(content) > 1024 {
		content = content[:1024]
	}

	if cs == "" && len(content) >= 2 {
		if content[0] == 0xfe && content[1] == 0xff {
			cs = "utf-16be"
		} else if content[0] == 0xff && content[1] == 0xfe {
			cs = "utf-16le"
		}
	}

	if cs == "" && len(content) >= 3 && content[0] == 0xef && content[1] == 0xbb && content[2] == 0xbf {
		cs = "utf-8"
	}

	if cs == "" && (strings.Contains(c.contentType, "html") || c.contentType == "") {
		// Look for a <meta> tag giving the encoding.
		tree, err := html.Parse(bytes.NewBuffer(content))
		if err == nil {
			for _, n := range metaCharsetSelector.MatchAll(tree) {
				a := make(map[string]string)
				for _, attr := range n.Attr {
					a[attr.Key] = attr.Val
				}
				if charsetAttr := a["charset"]; charsetAttr != "" {
					cs = strings.ToLower(charsetAttr)
					break
				}
				if strings.EqualFold(a["http-equiv"], "Content-Type") {
					cs = charsetFromContentType(a["content"])
					if cs != "" {
						break
					}
				}
			}
		}
	}

	if cs == "" {
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
			cs = "utf-8"
		}
	}

	if cs == "" {
		cs = "windows-1252"
	}

	if ce := compatibilityEncodings[cs]; ce != "" {
		cs = ce
	}

	c.charset = cs
}

func charsetFromContentType(t string) string {
	t = strings.ToLower(t)

	for t != "" {
		i := strings.Index(t, "charset")
		if i == -1 {
			return ""
		}
		t = t[len("charset"):]
		t = strings.TrimLeft(t, " \t\r\n\f")
		if !strings.HasPrefix(t, "=") {
			continue
		}
		t = strings.TrimLeft(t[1:], " \t\r\n\f")
		if t == "" {
			return ""
		}
		switch t[0] {
		case '"', '\'':
			quote := t[0]
			for j := 1; j < len(t); j++ {
				if t[j] == quote {
					return t[1:j]
				}
			}
			return ""
		default:
			j := strings.IndexAny(t, " ;\t\t\n\f")
			if j == -1 {
				return t
			}
			return t[:j]
		}
	}
	return ""
}

// compatibilityEncodings contains character sets that should be misinterpreted
// for compatibility. The encodings that are commented out are not yet
// implemented by the Mahonia library.
var compatibilityEncodings = map[string]string{
	//	"euc-kr":         "windows-949",
	//	"euc-jp":         "cp51932",
	//	"gb2312":         "gbk",
	//	"gb_2312-80":     "gbk",
	//	"iso-2022-jp":    "cp50220",
	"iso-8859-1":  "windows-1252",
	"iso-8859-9":  "windows-1254",
	"iso-8859-11": "windows-874",
	//	"ks_c_5601-1987": "windows-949",
	//	"shift_jis":      "windows-31j",
	"tis-620":  "windows-874",
	"us-ascii": "windows-1252",
}
