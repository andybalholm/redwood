package main

// URL matching and regular expressions

import (
	"log"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

type regexRule struct {
	rule
	*regexp.Regexp
}

// A regexMap is a set of regular-expression rules.
// As an optimization, it uses Aho-Corasick string matching find which regular
// expressions might match—instead of trying them all.
type regexMap struct {
	stringList phraseList
	rules      map[string][]regexRule
}

func newRegexMap() *regexMap {
	return &regexMap{
		stringList: newPhraseList(),
		rules:      make(map[string][]regexRule),
	}
}

func (rm *regexMap) findMatches(s string, tally map[rule]int) {
	if len(rm.rules) == 0 {
		return
	}

	tried := map[string]bool{}
	scanner := newPhraseScanner(rm.stringList, func(p string) {
		if tried[p] {
			return
		}
		for _, r := range rm.rules[p] {
			if r.MatchString(s) {
				tally[r.rule] = 1
			}
		}
		tried[p] = true
	})

	for i := 0; i < len(s); i++ {
		scanner.scanByte(s[i])
	}

	// Now try the regexes that have no distinctive literal string component.
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

	ss, err := regexStrings(s)
	if err != nil || ss.minLen() == 0 {
		// Store this rule in the list of rules without a literal string component.
		rm.rules[""] = append(rm.rules[""], regexRule{r, re})
		return
	}

	for _, p := range ss {
		rm.stringList.addPhrase(p)
		rm.rules[p] = append(rm.rules[p], regexRule{r, re})
	}
}

type URLMatcher struct {
	fragments     map[string]rule // a set of domain or domain+path URL fragments to test against
	regexes       *regexMap       // to match whole URL
	hostRegexes   *regexMap       // to match hostname only
	domainRegexes *regexMap
	pathRegexes   *regexMap
	queryRegexes  *regexMap
}

// finalize should be called after all rules have been added, but before
// using the URLMatcher.
func (m *URLMatcher) finalize() {
	m.regexes.stringList.findFallbackNodes(0, nil)
	m.hostRegexes.stringList.findFallbackNodes(0, nil)
	m.domainRegexes.stringList.findFallbackNodes(0, nil)
	m.pathRegexes.stringList.findFallbackNodes(0, nil)
	m.queryRegexes.stringList.findFallbackNodes(0, nil)
}

func newURLMatcher() *URLMatcher {
	m := new(URLMatcher)
	m.fragments = make(map[string]rule)
	m.regexes = newRegexMap()
	m.hostRegexes = newRegexMap()
	m.domainRegexes = newRegexMap()
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
	case domainRegex:
		m.domainRegexes.addRule(r)
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

	// strip off the port number, if present
	colon := strings.LastIndex(host, ":")
	// IPv6 addresses contain colons inside brackets, so be careful.
	if colon != -1 && !strings.Contains(host[colon:], "]") {
		host = host[:colon]
	}

	host = strings.TrimSuffix(host, ".")

	// Find the main domain name (e.g. "google" in "www.google.com").
	suffix := publicsuffix.List.PublicSuffix(host)
	if suffix != "" && suffix != host {
		domain := host[:len(host)-len(suffix)-1]
		dot := strings.LastIndex(domain, ".")
		if dot != -1 {
			domain = domain[dot+1:]
		}
		if idn, err := idna.ToUnicode(domain); err == nil {
			domain = idn
		}
		m.domainRegexes.findMatches(domain, result)
	}

	if idn, err := idna.ToUnicode(host); err == nil {
		host = idn
	}

	urlString := ""
	if u.Scheme != "" {
		urlString += strings.ToLower(u.Scheme) + ":"
	}
	if host != "" {
		urlString += "//" + host
		m.hostRegexes.findMatches(host, result)
	}

	path := strings.ToLower(u.Path)
	m.pathRegexes.findMatches(path, result)
	urlString += path

	query := strings.ToLower(u.RawQuery)
	if query != "" {
		q, err := url.QueryUnescape(query)
		if err == nil {
			// Change ' ' back to '+'.
			query = strings.Replace(q, " ", "+", -1)
		}
		m.queryRegexes.findMatches(query, result)
		urlString += "?" + query
	}

	m.regexes.findMatches(urlString, result)

	// Test for matches of the host and of the domains it belongs to.
	s := host
	for {
		// Test for matches with the path.
		s2 := s + path
		for {
			if r, ok := m.fragments[s2]; ok {
				result[r] = 1
			}
			slash := strings.LastIndex(s2, "/")
			if slash < 1 {
				// It's either not found, or at the first character.
				break
			}
			s2 = s2[:slash]
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
