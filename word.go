package main

import (
	"io"
	"mahonia.googlecode.com/hg"
	"os"
	"unicode"
	"utf8"
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

// A wordReader applies two filters to the data from another os.Reader:
// first it decodes the character set; then it applies wordRune to each character
// and removes extra spaces.
type wordReader struct {
	buf      []byte
	rd       io.Reader
	decode   mahonia.Decoder
	r, w     int
	err      os.Error
	prevRune int
}

func newWordReader(rd io.Reader, d mahonia.Decoder) *wordReader {
	b := new(wordReader)
	b.buf = make([]byte, 4096)
	b.rd = rd
	b.decode = d
	return b
}

// fill reads a new chunk into the buffer.
func (b *wordReader) fill() {
	// Slide existing data to beginning.
	if b.r > 0 {
		copy(b.buf, b.buf[b.r:b.w])
		b.w -= b.r
		b.r = 0
	}

	// Read new data.
	n, e := b.rd.Read(b.buf[b.w:])
	b.w += n
	if e != nil {
		b.err = e
	}
}

// Read reads data into p.
// It returns the number of bytes read into p.
// It calls Read at most once on the underlying Reader,
// hence n may be less than len(p).
// At EOF, the count will be zero and err will be os.EOF.
func (b *wordReader) Read(p []byte) (n int, err os.Error) {
	n = len(p)
	filled := false
	if n == 0 {
		return 0, b.err
	}
	if b.w == b.r {
		if b.err != nil {
			return 0, b.err
		}
		if n > len(b.buf) {
			// Large read, empty buffer.
			// Allocate a larger buffer for efficiency.
			b.buf = make([]byte, n)
		}
		b.fill()
		filled = true
		if b.w == b.r {
			return 0, b.err
		}
	}

	i := 0
	prev := b.prevRune
	for i < n {
		rune, size, status := b.decode(b.buf[b.r:b.w])

		if status == mahonia.STATE_ONLY {
			b.r += size
			continue
		}

		if status == mahonia.NO_ROOM {
			if b.err != nil {
				rune = 0xfffd
				size = b.w - b.r
				if size == 0 {
					break
				}
				status = mahonia.INVALID_CHAR
			} else if filled {
				break
			} else {
				b.fill()
				filled = true
				continue
			}
		}

		rune = wordRune(rune)
		if rune == ' ' && prev == ' ' {
			b.r += size
			continue
		}

		if i+utf8.RuneLen(rune) > n {
			break
		}

		b.r += size
		if rune < 128 {
			p[i] = byte(rune)
			i++
		} else {
			i += utf8.EncodeRune(p[i:], rune)
		}
		prev = rune
	}

	b.prevRune = prev
	return i, nil
}
