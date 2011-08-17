package main

// URL matching and regular expressions

import (
	"http"
	"log"
	"exp/regexp"
	"strings"
)

type regexMap map[string]*regexp.Regexp // A map from rules to compiled regexes

type URLMatcher struct {
	fragments    map[string]bool // a set of domain or domain+path URL fragments to test against
	regexes      regexMap        // to match whole URL
	hostRegexes  regexMap        // to match hostname only
	pathRegexes  regexMap
	queryRegexes regexMap
}

func newURLMatcher() *URLMatcher {
	m := new(URLMatcher)
	m.fragments = make(map[string]bool)
	m.regexes = make(regexMap)
	m.hostRegexes = make(regexMap)
	m.pathRegexes = make(regexMap)
	m.queryRegexes = make(regexMap)
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

		scopeChar := rule[len(rule)-1] // suffix to indicate regex scope, or '/' if no suffix

		var s string
		if scopeChar == '/' {
			s = rule[1 : len(rule)-1]
		} else {
			s = rule[1 : len(rule)-2]
		}
		re, err := regexp.Compile("(?i:" + s + ")")
		if err != nil {
			log.Printf("Error parsing URL regular expression %s: %v", rule, err)
			return
		}

		switch scopeChar {
		case '/':
			m.regexes[rule] = re
		case 'h':
			m.hostRegexes[rule] = re
		case 'p':
			m.pathRegexes[rule] = re
		case 'q':
			m.queryRegexes[rule] = re
		}
	}

	m.fragments[rule] = true
}

func (rm regexMap) findMatches(s string, tally map[string]int) {
	for rule, re := range rm {
		if re.MatchString(s) {
			tally[rule] = 1
		}
	}
}

// MatchingRules returns a list of the rules that u matches.
// For consistency with phrase matching, it is a map with rules for keys
// and with all values equal to 1.
func (m *URLMatcher) MatchingRules(u *http.URL) map[string]int {
	result := make(map[string]int)

	host := strings.ToLower(u.Host)
	path := strings.ToLower(u.Path)

	// strip off the port number, if present
	colon := strings.LastIndex(host, ":")
	if colon != -1 {
		host = host[:colon]
	}

	m.regexes.findMatches(u.String(), result)
	m.hostRegexes.findMatches(host, result)
	m.pathRegexes.findMatches(u.Path, result)
	m.queryRegexes.findMatches(u.RawQuery, result)

	// Test for matches of the host and of the domains it belongs to.
	s := host
	for {
		if m.fragments[s] {
			result[s] = 1
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
			result[s] = 1
		}
		slash := strings.LastIndex(s[:len(s)-1], "/")
		if slash == -1 {
			break
		}
		s = s[:slash+1]
	}

	return result
}
