package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"

	"golang.org/x/net/html"
)

func (c *config) readCensoredWordsFile(filename string) error {
	if c.CensoredWords == nil {
		c.CensoredWords = make(map[string]bool)
	}

	f, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("could not open %s: %s", filename, err)
	}
	defer f.Close()
	cr := newConfigReader(f)

	for {
		line, err := cr.ReadLine()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		c.CensoredWords[strings.ToLower(line)] = true
	}

	return nil
}

// censor returns s, with all words from censored removed.
func censor(s string, censored map[string]bool) string {
	inWord := false
	changed := false
	copied := 0
	var wordStart int
	var result []byte

	for i, c := range s {
		wordChar := unicode.IsLetter(c) || unicode.IsMark(c) || c == '\'' || c == '-'
		switch {
		case wordChar && !inWord:
			wordStart = i
			inWord = true

		case inWord && !wordChar:
			word := strings.ToLower(s[wordStart:i])
			if censored[word] {
				result = append(result, s[copied:wordStart]...)
				copied = i
				changed = true
				// Skip a space before or after, but not both.
				if c == ' ' {
					copied++
				} else if len(result) > 0 && result[len(result)-1] == ' ' {
					result = result[:len(result)-1]
				}
			}
			inWord = false
		}
	}

	if inWord {
		word := strings.ToLower(s[wordStart:len(s)])
		if censored[word] {
			result = append(result, s[copied:wordStart]...)
			copied = len(s)
			changed = true
		}
	}

	if changed {
		result = append(result, s[copied:]...)
		return string(result)
	}

	return s
}

// censorHTML removes censored words from the text content of n and its
// children.
func censorHTML(n *html.Node, censored map[string]bool) (changed bool) {
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		switch c.Type {
		case html.TextNode:
			newText := censor(c.Data, censored)
			if newText != c.Data {
				c.Data = newText
				changed = true
			}
		case html.ElementNode:
			switch c.Data {
			case "script", "style", "code", "pre":
				// Don't censor code.
			default:
				if censorHTML(c, censored) {
					changed = true
				}
			}
		}
	}

	return changed
}
