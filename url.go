package main

// URL matching and regular expressions

import (
	"log"
	"net/url"
	"regexp"
	"strings"
)

// A regexMap is a map from rules to compiled regexes,
// except that some are stored as plain strings to search for instead.
type regexMap struct {
	regexes map[rule]*regexp.Regexp
	strings map[rule]string
}

func newRegexMap() *regexMap {
	return &regexMap{make(map[rule]*regexp.Regexp), make(map[rule]string)}
}

func (rm *regexMap) findMatches(s string, tally map[rule]int) {
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

// addRule adds a rule to the map.
func (rm *regexMap) addRule(r rule) {
	if _, alreadyHave := rm.regexes[r]; alreadyHave {
		return
	}
	if _, alreadyHave := rm.strings[r]; alreadyHave {
		return
	}

	s := r.content
	if s == regexp.QuoteMeta(s) {
		rm.strings[r] = s
		return
	}

	re, err := regexp.Compile(s)
	if err != nil {
		log.Printf("Error parsing URL regular expression %s: %v", r, err)
		return
	}
	rm.regexes[r] = re
}

type URLMatcher struct {
	fragments    map[string]rule // a set of domain or domain+path URL fragments to test against
	regexes      *regexMap       // to match whole URL
	hostRegexes  *regexMap       // to match hostname only
	pathRegexes  *regexMap
	queryRegexes *regexMap
}

func newURLMatcher() *URLMatcher {
	m := new(URLMatcher)
	m.fragments = make(map[string]rule)
	m.regexes = newRegexMap()
	m.hostRegexes = newRegexMap()
	m.pathRegexes = newRegexMap()
	m.queryRegexes = newRegexMap()
	return m
}

// AddRule adds a rule to the matcher (unless it's already there).
func (m *URLMatcher) AddRule(r rule) {
	switch r.t {
	case urlMatch:
		m.fragments[r.content] = r
	case urlRegex:
		m.regexes.addRule(r)
	case hostRegex:
		m.hostRegexes.addRule(r)
	case pathRegex:
		m.pathRegexes.addRule(r)
	case queryRegex:
		m.queryRegexes.addRule(r)
	}
}

// MatchingRules returns a list of the rules that u matches.
// For consistency with phrase matching, it is a map with rules for keys
// and with all values equal to 1.
func (m *URLMatcher) MatchingRules(u *url.URL) map[rule]int {
	result := make(map[rule]int)

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
		if r, ok := m.fragments[s]; ok {
			result[r] = 1
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
		if r, ok := m.fragments[s]; ok {
			result[r] = 1
		}
		slash := strings.LastIndex(s[:len(s)-1], "/")
		if slash == -1 {
			break
		}
		s = s[:slash+1]
	}

	return result
}

// fixConnectURL takes a "URL" that is just a host and port, such as from a
// CONNECT request, and makes it useable.
func fixConnectURL(u *url.URL) *url.URL {
	if u.Host == "" {
		return &url.URL{Host: u.String()}
	}
	return u
}
