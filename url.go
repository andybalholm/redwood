package main

// URL matching and regular expressions

import (
	"code.google.com/p/go-idn/idna/punycode"
	"log"
	"net/url"
	"regexp"
	"strings"
)

type regexRule struct {
	rule
	*regexp.Regexp
}

// A regexMap is a set of regular-expression rules.
// As an optimization, it uses Aho-Corasick string matching find which regular
// expressions might match—instead of trying them all.
type regexMap struct {
	prefixList phraseList
	rules      map[string][]regexRule
}

func newRegexMap() *regexMap {
	return &regexMap{
		prefixList: newPhraseList(),
		rules:      make(map[string][]regexRule),
	}
}

func (rm *regexMap) findMatches(s string, tally map[rule]int) {
	tried := map[string]bool{}
	scanner := newPhraseScanner(rm.prefixList, func(prefix string) {
		if tried[prefix] {
			return
		}
		for _, r := range rm.rules[prefix] {
			if r.MatchString(s) {
				tally[r.rule] = 1
			}
		}
		tried[prefix] = true
	})

	for i := 0; i < len(s); i++ {
		scanner.scanByte(s[i])
	}

	// Now try the regexes that have no literal string prefix.
	for _, r := range rm.rules[""] {
		if r.MatchString(s) {
			tally[r.rule] = 1
		}
	}
}

// addRule adds a rule to the map.
func (rm *regexMap) addRule(r rule) {
	s := r.content

	re, err := regexp.Compile(s)
	if err != nil {
		log.Printf("Error parsing URL regular expression %s: %v", r, err)
		return
	}

	prefix, _ := re.LiteralPrefix()
	if prefix != "" {
		rm.prefixList.addPhrase(prefix)
	}
	rm.rules[prefix] = append(rm.rules[prefix], regexRule{r, re})
}

type URLMatcher struct {
	fragments    map[string]rule // a set of domain or domain+path URL fragments to test against
	regexes      *regexMap       // to match whole URL
	hostRegexes  *regexMap       // to match hostname only
	pathRegexes  *regexMap
	queryRegexes *regexMap
}

// finalize should be called after all rules have been added, but before 
// using the URLMatcher.
func (m *URLMatcher) finalize() {
	m.regexes.prefixList.findFallbackNodes(0, nil)
	m.hostRegexes.prefixList.findFallbackNodes(0, nil)
	m.pathRegexes.prefixList.findFallbackNodes(0, nil)
	m.queryRegexes.prefixList.findFallbackNodes(0, nil)
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

	// Handle internationalized domain names.
	if strings.Contains(host, "xn--") {
		labels := strings.Split(host, ".")
		for i, puny := range labels {
			if !strings.HasPrefix(puny, "xn--") {
				continue
			}
			uni, err := punycode.DecodeString(puny[len("xn--"):])
			if err == nil {
				labels[i] = uni
			}
		}
		host = strings.ToLower(strings.Join(labels, "."))
	}

	m.regexes.findMatches(strings.ToLower(u.String()), result)
	m.hostRegexes.findMatches(strings.ToLower(u.Scheme) + "://" + host, result)
	m.pathRegexes.findMatches(path, result)
	m.queryRegexes.findMatches(strings.ToLower(u.RawQuery), result)

	// Test for matches of the host and of the domains it belongs to.
	s := host
	for {
		// Test for matches with the path.
		s2 := s + path
		for {
			if r, ok := m.fragments[s2]; ok {
				result[r] = 1
			}
			slash := strings.LastIndex(s2[:len(s2)-1], "/")
			if slash == -1 {
				break
			}
			s2 = s2[:slash+1]
		}

		if r, ok := m.fragments[s]; ok {
			result[r] = 1
		}
		dot := strings.Index(s, ".")
		if dot == -1 {
			break
		}
		s = s[dot+1:]
	}

	return result
}
