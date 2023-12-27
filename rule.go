package main

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// A simpleRule is a URL fragment, URL regular expression, or content phrase
// that will be matched against a page in the process of determining its score.
type simpleRule struct {
	t       ruleType
	content string
}

type ruleType int

const (
	defaultRule ruleType = iota
	urlMatch
	ipAddr
	urlRegex
	hostRegex
	domainRegex
	pathRegex
	queryRegex
	contentPhrase
	imageHash
	urlList
)

func (r simpleRule) String() string {
	switch r.t {
	case defaultRule:
		return "default"
	case urlMatch:
		return r.content
	case ipAddr:
		return "ip:" + r.content
	case urlRegex, hostRegex, domainRegex, pathRegex, queryRegex:
		suffix := ""
		switch r.t {
		case hostRegex:
			suffix = "h"
		case pathRegex:
			suffix = "p"
		case queryRegex:
			suffix = "q"
		case domainRegex:
			suffix = "d"
		}
		return "/" + r.content + "/" + suffix
	case contentPhrase:
		return "<" + r.content + ">"
	case imageHash:
		return "%" + r.content
	case urlList:
		return "urllist " + r.content
	}
	panic(fmt.Errorf("invalid rule type: %d", r.t))
}

// parseSimpleRule parses a rule from the beginning of s, returning the rule
// and any remaining unconsumed characters from s.
func parseSimpleRule(s string) (r simpleRule, leftover string, err error) {
	s = strings.TrimLeft(s, " \t\r\n\f")
	if s == "" {
		return simpleRule{}, "", errors.New("blank rule")
	}

	switch s[0] {
	case '/':
		r.t = urlRegex
		space := strings.Index(s, " ")
		var slash int
		if space == -1 {
			slash = strings.LastIndex(s, "/")
		} else {
			slash = strings.LastIndex(s[:space], "/")
		}
		if slash == 0 {
			return simpleRule{}, s, errors.New("unmatched slash")
		}
		r.content = s[1:slash]
		s = s[slash+1:]
		if s != "" {
			switch s[0] {
			case 'h':
				r.t = hostRegex
				s = s[1:]
			case 'p':
				r.t = pathRegex
				s = s[1:]
			case 'q':
				r.t = queryRegex
				s = s[1:]
			case 'd':
				r.t = domainRegex
				s = s[1:]
			}
		}
	case '<':
		r.t = contentPhrase
		bracket := strings.Index(s, ">")
		if bracket == -1 {
			return simpleRule{}, s, errors.New("unmatched '<'")
		}
		r.content = wordString(s[1:bracket])
		s = s[bracket+1:]
	case '%':
		r.t = imageHash
		space := strings.Index(s, " ")
		if space == -1 {
			r.content = s[1:]
			s = ""
		} else {
			r.content = s[1:space]
			s = s[space:]
		}
		r.content = strings.ToLower(r.content)
	default:
		if strings.HasPrefix(s, "urllist ") {
			s = strings.TrimPrefix(s, "urllist ")
			var filename string
			filename, s, _ = strings.Cut(s, " ")
			return simpleRule{
				t:       urlList,
				content: filename,
			}, s, nil
		}

		if c, _ := utf8.DecodeRuneInString(s); unicode.IsLetter(c) || unicode.IsDigit(c) {
			r.t = urlMatch
			space := strings.Index(s, " ")
			if space == -1 {
				r.content = strings.ToLower(s)
				s = ""
			} else {
				r.content = strings.ToLower(s[:space])
				s = s[space:]
			}
			if r.content == "default" {
				r.t = defaultRule
			}
			if strings.HasSuffix(r.content, "/") {
				r.content = r.content[:len(r.content)-1]
			}
			if strings.HasPrefix(r.content, "ip:") {
				r.t = ipAddr
				r.content = strings.TrimPrefix(r.content, "ip:")
			}
		} else {
			return simpleRule{}, s, fmt.Errorf("invalid rule: %q", s)
		}
	}

	return r, s, nil
}

func (simpleRule) isARule() {}

type rule interface {
	isARule()
	fmt.Stringer
}

// a compoundRule is two rules (or compoundRules) joined by a boolean operator
// (&, |, or &! [AND NOT]).
type compoundRule struct {
	left  rule
	op    string
	right rule
}

func (compoundRule) isARule() {}

func parenthesesIfCompound(r rule) string {
	switch r := r.(type) {
	case compoundRule:
		return "(" + r.String() + ")"
	default:
		return r.String()
	}
}

func (r compoundRule) String() string {
	return parenthesesIfCompound(r.left) + " " + r.op + " " + parenthesesIfCompound(r.right)
}

func parseCompoundRule(s string) (rule, string, error) {
	left, afterLeft, err := alt(
		delimited(tag("("), parseCompoundRule, tag(")")),
		func(s string) (rule, string, error) { return parseSimpleRule(s) },
	)(s)
	if err != nil {
		return nil, s, err
	}

	op, afterOp, err := alt(
		tag("&!"),
		tag("&"),
		tag("|"),
	)(afterLeft)
	if err != nil {
		// Since there's no operator, it's actually a simple rule.
		// Return it.
		return left, afterLeft, nil
	}

	right, afterRight, err := alt(
		delimited(tag("("), parseCompoundRule, tag(")")),
		func(s string) (rule, string, error) { return parseSimpleRule(s) },
	)(afterOp)
	if err != nil {
		return nil, afterRight, err
	}

	return compoundRule{left, op, right}, afterRight, nil
}
