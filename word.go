package main

import (
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/transform"
)

// wordRune maps c into a reduced set of "word" characters.
// If c is a letter, it returns it in lowercase.
// It it it is a digit, it returns it unchanged.
// Otherwise it returns a space.
func wordRune(c rune) rune {
	switch {
	case c >= 'a' && c <= 'z' || c >= '0' && c <= '9':
		return c
	case c >= 'A' && c <= 'Z':
		return c + ('a' - 'A')
	case c < 128:
		return ' '
	case unicode.IsDigit(c):
		return c
	case unicode.IsLetter(c):
		return unicode.ToLower(c)
	}

	return ' '
}

// wordString applies wordRune to each character in s and removes extra spaces.
func wordString(s string) string {
	runes := make([]rune, 0, 20)
	prevRune := '\x00'

	for _, c := range s {
		c = wordRune(c)
		if c != ' ' || prevRune != ' ' {
			runes = append(runes, c)
		}
		prevRune = c
	}

	return string(runes)
}

// A wordTransformer does the same transformation as wordString, but in a
// streaming fashion.
type wordTransformer struct {
	prevRune rune
}

func (t *wordTransformer) Transform(dst, src []byte, atEOF bool) (nDst, nSrc int, err error) {
	for nSrc < len(src) {
		r, n := utf8.DecodeRune(src[nSrc:])
		if r == utf8.RuneError && !atEOF && !utf8.FullRune(src[nSrc:]) {
			err = transform.ErrShortSrc
			return
		}
		r = wordRune(r)
		if r == ' ' && t.prevRune == ' ' {
			nSrc += n
			continue
		}
		if nDst+utf8.RuneLen(r) > len(dst) {
			err = transform.ErrShortDst
			return
		}

		t.prevRune = r
		nSrc += n
		nDst += utf8.EncodeRune(dst[nDst:], r)
	}
	return
}

func (t *wordTransformer) Reset() {
	t.prevRune = 0
}
