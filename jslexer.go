package main

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// A lexer for extracting quoted strings from JavaScript.
// Based on Rob Pike's Lexical Scanning talk and https://bitbucket.org/ned/jslex

// lexer holds the state of the scanner.
type lexer struct {
	input string      // the string being scanned.
	start int         // start position of this item.
	pos   int         // current position in the input.
	width int         // width of last rune read from input.
	items chan string // channel of scanned items.
	divOK bool        // Does a slash mean division? (as opposed to regex)
}

func lex(input string) (*lexer, chan string) {
	l := &lexer{
		input: input,
		items: make(chan string),
	}
	go l.run() // Concurrently run state machine.
	return l, l.items
}

// run lexes the input by executing state functions until
// the state is nil.
func (l *lexer) run() {
	for state := lexText; state != nil; {
		state = state(l)
	}
	close(l.items) // No more tokens will be delivered.
}

// emitString passes a string back to the client.
func (l *lexer) emitString() {
	quote := l.input[l.start]
	s := l.input[l.start+1 : l.pos]
	if len(s) > 0 && s[len(s)-1] == quote {
		s = s[:len(s)-1]
	}
	l.start = l.pos
	if !strings.Contains(s, "\\") {
		l.items <- s
		return
	}

	b := make([]byte, 0, len(s))
	for len(s) > 0 {
		backslash := strings.Index(s, "\\")
		if backslash == -1 {
			b = append(b, s...)
			break
		}
		b = append(b, s[:backslash]...)
		if backslash == len(s)-1 {
			break
		}
		c := s[backslash+1]
		end := backslash + 2
		switch c {
		case '0':
			b = append(b, 0)
		case '\n', '\r', '\f':
			// skip the line termination.
		case 'b':
			b = append(b, '\b')
		case 't':
			b = append(b, '\t')
		case 'n':
			b = append(b, '\n')
		case 'v':
			b = append(b, '\v')
		case 'f':
			b = append(b, '\f')
		case 'r':
			b = append(b, '\r')
		case 'x':
			if len(s) < backslash+4 {
				break
			}
			r, err := strconv.ParseUint(s[backslash+2:backslash+4], 16, 8)
			if err != nil {
				break
			}
			b = append(b, string(r)...)
			end = backslash + 4
		case 'u':
			if len(s) < backslash+6 {
				break
			}
			r, err := strconv.ParseUint(s[backslash+2:backslash+6], 16, 16)
			if err != nil {
				break
			}
			b = append(b, string(r)...)
			end = backslash + 6
		default:
			b = append(b, c)

		}
		s = s[end:]
	}
	l.items <- string(b)
}

const eof = -1

// next returns the next rune in the input.
func (l *lexer) next() (c rune) {
	if l.pos >= len(l.input) {
		l.width = 0
		return eof
	}
	c, l.width =
		utf8.DecodeRuneInString(l.input[l.pos:])
	l.pos += l.width
	return c
}

// ignore skips over the pending input before this point.
func (l *lexer) ignore() {
	l.start = l.pos
}

// backup steps back one rune.
// Can be called only once per call of next.
func (l *lexer) backup() {
	l.pos -= l.width
}

// peek returns but does not consume
// the next rune in the input.
func (l *lexer) peek() rune {
	c := l.next()
	l.backup()
	return c
}

// accept consumes the next rune
// if it's from the valid set.
func (l *lexer) accept(valid string) bool {
	if strings.IndexRune(valid, l.next()) >= 0 {
		return true
	}
	l.backup()
	return false
}

// acceptRun consumes a run of runes from the valid set.
func (l *lexer) acceptRun(valid string) {
	for strings.IndexRune(valid, l.next()) >= 0 {
	}
	l.backup()
}

// error terminates parsing and emits the remaining input as a string.
func (l *lexer) error() stateFn {
	l.items <- l.input[l.start:]
	return nil
}

// stateFn represents the state of the scanner
// as a function that returns the next state.
type stateFn func(*lexer) stateFn

func lexNumber(l *lexer) stateFn {
	// Optional leading sign.
	l.accept("+-")
	// Is it hex?
	digits := "0123456789"
	if l.accept("0") && l.accept("xX") {
		digits = "0123456789abcdefABCDEF"
	}
	l.acceptRun(digits)
	if l.accept(".") {
		l.acceptRun(digits)
	}
	if l.accept("eE") {
		l.accept("+-")
		l.acceptRun("0123456789")
	}
	l.ignore()
	l.divOK = true
	return lexText
}

func lexText(l *lexer) stateFn {
	for {
		switch r := l.next(); r {
		case eof:
			return nil
		case ' ', '\t', '\n':
			l.ignore()
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			l.backup()
			return lexNumber
		case '.':
			r2 := l.peek()
			if '0' <= r2 && r2 <= '9' {
				l.pos--
				return lexNumber
			}
			l.ignore()
			l.divOK = false
		case '/':
			return lexAfterSlash
		case '_', '$', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z':
			l.backup()
			return lexIdentifier
		case '\'', '"':
			l.backup()
			return lexString
		case '(', ':', ';', '?', '[', '{', '}', '~':
			l.divOK = false
			l.ignore()
		case ')', ']':
			l.divOK = true
			l.ignore()
		case '!', '=':
			if len(l.input) > l.pos && l.input[l.pos] == '=' {
				l.pos++
				if len(l.input) > l.pos && l.input[l.pos] == '=' {
					l.pos++
				}
			}
			l.divOK = false
			l.ignore()
		case '%', '*', '^':
			if len(l.input) > l.pos && l.input[l.pos] == '=' {
				l.pos++
			}
			l.divOK = false
			l.ignore()
		case '&', '|':
			if len(l.input) > l.pos {
				if r2 := l.input[l.pos]; r2 == byte(r) || r2 == '=' {
					l.pos++
				}
			}
			l.divOK = false
			l.ignore()
		case '+', '-':
			l.divOK = false
			if len(l.input) > l.pos {
				switch r2 := l.input[l.pos]; r2 {
				case byte(r):
					l.divOK = true
					l.pos++
				case '=':
					l.pos++
				}
			}
			l.ignore()
		case '<':
			if len(l.input) > l.pos && l.input[l.pos] == '<' {
				l.pos++
			}
			if len(l.input) > l.pos && l.input[l.pos] == '=' {
				l.pos++
			}
			l.divOK = false
			l.ignore()
		case '>':
			if len(l.input) > l.pos && l.input[l.pos] == '>' {
				l.pos++
				if len(l.input) > l.pos && l.input[l.pos] == '>' {
					l.pos++
				}
			}
			if len(l.input) > l.pos && l.input[l.pos] == '=' {
				l.pos++
			}
			l.divOK = false
			l.ignore()

		default:
			if unicode.IsLetter(r) {
				l.backup()
				return lexIdentifier
			}
			l.ignore()
		}
	}
	panic("unreachable")
}

func lexAfterSlash(l *lexer) stateFn {
	r := l.next()
	switch r {
	case '*':
		return lexBlockComment
	case '/':
		return lexLineComment
	}

	if l.divOK {
		if r != '=' {
			l.backup()
		}
		l.ignore()
		l.divOK = false
		return lexText
	}

	l.backup()
	return lexRegex
}

func lexBlockComment(l *lexer) stateFn {
	// The opening "/*" has already been read.
	closing := strings.Index(l.input[l.pos:], "*/")
	if closing == -1 {
		l.pos = len(l.input)
		return l.error()
	}
	l.pos += closing + len("*/")
	l.ignore()
	return lexText
}

func lexLineComment(l *lexer) stateFn {
	// The opening "//" has already been read.
	newline := strings.Index(l.input[l.pos:], "\n")
	if newline == -1 {
		l.pos = len(l.input)
	} else {
		l.pos += newline
	}
	l.ignore()
	return lexText
}

func lexIdentifier(l *lexer) stateFn {
	for {
		r := l.next()
		if !(r == '_' || r == '$' || unicode.IsLetter(r) || unicode.IsDigit(r)) {
			break
		}
	}
	l.backup()
	divOK, ok := keywordDivOK[l.input[l.start:l.pos]]
	if ok {
		l.divOK = divOK
		l.ignore()
		return lexText
	}

	l.divOK = true
	l.ignore()
	return lexText
}

func lexString(l *lexer) stateFn {
	quote := l.next()
	for {
		r := l.next()
		if r == quote || r == eof {
			break
		}
		if r == '\\' {
			l.next()
		}
	}
	l.emitString()
	l.divOK = true
	return lexText
}

// regexRegex is a regular expression for recognizing JS regular expressions.
// The initial slash has already been read.
var regexRegex = regexp.MustCompile(`^([^*\\/\[]|\\.|\[([^\]\\]|\\.)*\])([^\\/\[]|\\.|\[([^\]\\]|\\.)*\])*/[a-zA-Z0-9]*`)

func lexRegex(l *lexer) stateFn {
	match := regexRegex.FindString(l.input[l.pos:])
	l.pos += len(match)
	l.ignore()
	l.divOK = true
	return lexText
}

// keywordDivOK contains a value of true for keywords that can be followed
// by a division operator.
var keywordDivOK = map[string]bool{
	"break":      false,
	"case":       false,
	"catch":      false,
	"class":      false,
	"const":      false,
	"continue":   false,
	"debugger":   false,
	"default":    false,
	"delete":     false,
	"do":         false,
	"else":       false,
	"enum":       false,
	"export":     false,
	"extends":    false,
	"finally":    false,
	"for":        false,
	"function":   false,
	"if":         false,
	"import":     false,
	"in":         false,
	"instanceof": false,
	"new":        false,
	"return":     false,
	"super":      false,
	"switch":     false,
	"this":       false,
	"throw":      false,
	"try":        false,
	"typeof":     false,
	"var":        false,
	"void":       false,
	"while":      false,
	"with":       false,
	"null":       true,
	"true":       true,
	"false":      true,
}
