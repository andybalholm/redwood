package main

// URL matching and regular expressions

import (
	"http"
	"log"
	"exp/regexp"
	"strings"
)

// A regexMap is a map from rules to compiled regexes,
// except that some are stored as plain strings to search for instead.
type regexMap struct {
	regexes map[string]*regexp.Regexp
	strings map[string]string
}

func newRegexMap() *regexMap {
	return &regexMap{make(map[string]*regexp.Regexp), make(map[string]string)}
}

func (rm *regexMap) findMatches(s string, tally map[string]int) {
	for rule, re := range rm.regexes {
		if re.MatchString(s) {
			tally[rule] = 1
		}
	}
	for rule, str := range rm.strings {
		if strings.Contains(s, str) {
			tally[rule] = 1
		}
	}
}

// addRule adds a rule to the map, where rule is the rule name,
// and s is the actual regex text.
func (rm *regexMap) addRule(rule, s string) {
	if _, alreadyHave := rm.regexes[rule]; alreadyHave {
		return
	}
	if _, alreadyHave := rm.strings[rule]; alreadyHave {
		return
	}

	if s == regexp.QuoteMeta(s) {
		rm.strings[rule] = s
		return
	}

	re, err := regexp.Compile(s)
	if err != nil {
		log.Printf("Error parsing URL regular expression %s: %v", rule, err)
		return
	}
	rm.regexes[rule] = re
}

type URLMatcher struct {
	fragments    map[string]bool // a set of domain or domain+path URL fragments to test against
	regexes      *regexMap       // to match whole URL
	hostRegexes  *regexMap       // to match hostname only
	pathRegexes  *regexMap
	queryRegexes *regexMap
}

func newURLMatcher() *URLMatcher {
	m := new(URLMatcher)
	m.fragments = make(map[string]bool)
	m.regexes = newRegexMap()
	m.hostRegexes = newRegexMap()
	m.pathRegexes = newRegexMap()
	m.queryRegexes = newRegexMap()
	return m
}

// AddRule adds a rule to the matcher (unless it's already there).
func (m *URLMatcher) AddRule(rule string) {
	if rule[0] == '/' {
		// regular expression
		scopeChar := rule[len(rule)-1] // suffix to indicate regex scope, or '/' if no suffix

		var s string
		if scopeChar == '/' {
			s = rule[1 : len(rule)-1]
		} else {
			s = rule[1 : len(rule)-2]
		}

		switch scopeChar {
		case '/':
			m.regexes.addRule(rule, s)
		case 'h':
			m.hostRegexes.addRule(rule, s)
		case 'p':
			m.pathRegexes.addRule(rule, s)
		case 'q':
			m.queryRegexes.addRule(rule, s)
		}

		return
	}

	m.fragments[rule] = true
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

	m.regexes.findMatches(strings.ToLower(u.String()), result)
	m.hostRegexes.findMatches(host, result)
	m.pathRegexes.findMatches(path, result)
	m.queryRegexes.findMatches(strings.ToLower(u.RawQuery), result)

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
