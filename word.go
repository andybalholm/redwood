package main

import (
	"unicode"
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
