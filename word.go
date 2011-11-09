package main

import (
	"io"
	"mahonia.googlecode.com/hg"
	"unicode"
	"unicode/utf8"
)

// wordRune maps c into a reduced set of "word" characters.
// If c is a letter, it returns it in lowercase.
// It it it is a digit, it returns it unchanged.
// Otherwise it returns a space.
func wordRune(c int) int {
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
	runes := make([]int, 0, 20)
	prevRune := 0

	for _, c := range s {
		c = wordRune(c)
		if c != ' ' || prevRune != ' ' {
			runes = append(runes, c)
		}
		prevRune = c
	}

	return string(runes)
}

// A wordReader applies two filters to the data from a slice of bytes:
// first it decodes the character set; then it applies wordRune to each character
// and removes extra spaces.
type wordReader struct {
	buf          []byte
	decode       mahonia.Decoder
	pos          int
	prevRune     int
	leftover     int // a rune that was decoded, but wouldn't fit in the output buffer
	leftoverSize int // the number of bytes occupied by the leftover rune
}

func newWordReader(data []byte, d mahonia.Decoder) *wordReader {
	return &wordReader{
		buf:    data,
		decode: d,
	}
}

// Read reads data into p.
// It returns the number of bytes read into p.
// At EOF, the count will be zero and err will be os.EOF.
func (b *wordReader) Read(p []byte) (n int, err error) {
	var rune, size int
	var status mahonia.Status
	for b.pos < len(b.buf) && n < len(p) {
		if b.leftoverSize == 0 {
			rune, size, status = b.decode(b.buf[b.pos:])
		} else {
			rune = b.leftover
			size = b.leftoverSize
			status = mahonia.SUCCESS
			b.leftover = 0
			b.leftoverSize = 0
		}

		if status == mahonia.STATE_ONLY {
			b.pos += size
			continue
		}

		if status == mahonia.NO_ROOM {
			rune = 0xfffd
			size = len(b.buf) - b.pos
			status = mahonia.INVALID_CHAR
		}

		rune = wordRune(rune)
		if rune == ' ' && b.prevRune == ' ' {
			b.pos += size
			continue
		}

		if rune < 128 {
			p[n] = byte(rune)
			n++
		} else if n+utf8.RuneLen(rune) > len(p) {
			b.leftover = rune
			b.leftoverSize = size
			break
		} else {
			n += utf8.EncodeRune(p[n:], rune)
		}

		b.pos += size
		b.prevRune = rune
	}

	if n == 0 && b.pos == len(b.buf) {
		return 0, io.EOF
	}

	return
}
