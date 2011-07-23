package main

// URL matching and regular expressions

import (
	"http"
	"log"
	"sre2.googlecode.com/hg/sre2"
	"strings"
)

type URLMatcher struct {
	fragments map[string]bool // a set of domain or domain+path URL fragments to test against
	regexes   map[string]sre2.Re
}

func newURLMatcher() *URLMatcher {
	m := new(URLMatcher)
	m.fragments = make(map[string]bool)
	m.regexes = make(map[string]sre2.Re)
	return m
}

// AddRule adds a rule to the matcher (unless it's already there).
func (m *URLMatcher) AddRule(rule string) {
	if rule[0] == '/' {
		// regular expression
		_, ok := m.regexes[rule]
		if ok {
			return
		}

		s := rule[1 : len(rule)-1]
		re, err := sre2.Parse("(?i)" + s)
		if err != nil {
			log.Printf("Error parsing URL regular expression %s: %v", rule, err)
			return
		}
		m.regexes[rule] = re
	}

	m.fragments[rule] = true
}

// MatchingRules returns a list of the rules that u matches.
func (m *URLMatcher) MatchingRules(u *http.URL) []string {
	var result []string

	s := u.String()
	for rule, re := range m.regexes {
		if re.Match(s) {
			result = append(result, rule)
		}
	}

	host := strings.ToLower(u.Host)
	path := strings.ToLower(u.Path)

	// strip off the port number, if present
	colon := strings.LastIndex(host, ":")
	if colon != -1 {
		host = host[:colon]
	}

	// Test for matches of the host and of the domains it belongs to.
	s = host
	for {
		if m.fragments[s] {
			result = append(result, s)
		}
		dot := strings.Index(s, ".")
		if dot == -1 {
			break
		}
		s = s[dot+1:]
	}

	// Test for matches with the path.
	s = host + path
	for {
		if m.fragments[s] {
			result = append(result, s)
		}
		slash := strings.LastIndex(s[:len(s)-1], "/")
		if slash == -1 {
			break
		}
		s = s[:slash+1]
	}

	return result
}
