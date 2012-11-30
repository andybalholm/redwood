// Copyright 2011 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file is based on http://code.google.com/p/codesearch/source/browse/index/regexp.go,
// modified to find strings instead of trigrams.

package main

import (
	"regexp/syntax"
	"sort"
	"strings"
	"unicode"
)

// regexStrings returns a set of strings such that any string that matches re must
// contain at least one of the strings in the set. If no such set can be found,
// regexStrings returns an empty set.
func regexStrings(re string) (stringSet, error) {
	parsed, err := syntax.Parse(re, syntax.Perl)
	if err != nil {
		return nil, err
	}
	info := analyze(parsed)
	return info.bestSet(), nil
}

// A regexpInfo summarizes the results of analyzing a regexp.
type regexpInfo struct {
	// canEmpty records whether the regexp matches the empty string
	canEmpty bool

	// exact is the exact set of strings matching the regexp.
	exact stringSet

	// if exact is nil, prefix is the set of possible match prefixes,
	// and suffix is the set of possible match suffixes.
	prefix stringSet // otherwise: the exact set of matching prefixes ...
	suffix stringSet // ... and suffixes

	// internal is a set of strings that match internally (not as prefixes or
	// suffixes).
	internal stringSet
}

const (
	// Exact sets are limited to maxExact strings.
	// If they get too big, simplify will rewrite the regexpInfo
	// to use prefix and suffix instead.  It's not worthwhile for
	// this to be bigger than maxSet.
	maxExact = 100

	// Prefix and suffix sets are limited to maxSet strings.
	// If they get too big, simplify will replace groups of strings
	// sharing a common leading prefix (or trailing suffix) with
	// that common prefix (or suffix).
	maxSet = 200
)

// anyMatch returns the regexpInfo describing a regexp that
// matches any string.
func anyMatch() regexpInfo {
	return regexpInfo{
		canEmpty: true,
		prefix:   []string{""},
		suffix:   []string{""},
	}
}

// anyChar returns the regexpInfo describing a regexp that
// matches any single character.
func anyChar() regexpInfo {
	return regexpInfo{
		prefix: []string{""},
		suffix: []string{""},
	}
}

// noMatch returns the regexpInfo describing a regexp that
// matches no strings at all.
func noMatch() regexpInfo {
	return regexpInfo{}
}

// emptyString returns the regexpInfo describing a regexp that
// matches only the empty string.
func emptyString() regexpInfo {
	return regexpInfo{
		canEmpty: true,
		exact:    []string{""},
	}
}

// analyze returns the regexpInfo for the regexp re.
func analyze(re *syntax.Regexp) (ret regexpInfo) {
	var info regexpInfo
	switch re.Op {
	case syntax.OpNoMatch:
		return noMatch()

	case syntax.OpEmptyMatch,
		syntax.OpBeginLine, syntax.OpEndLine,
		syntax.OpBeginText, syntax.OpEndText,
		syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return emptyString()

	case syntax.OpLiteral:
		if re.Flags&syntax.FoldCase != 0 {
			switch len(re.Rune) {
			case 0:
				return emptyString()
			case 1:
				// Single-letter case-folded string:
				// rewrite into char class and analyze.
				re1 := &syntax.Regexp{
					Op: syntax.OpCharClass,
				}
				re1.Rune = re1.Rune0[:0]
				r0 := re.Rune[0]
				re1.Rune = append(re1.Rune, r0, r0)
				for r1 := unicode.SimpleFold(r0); r1 != r0; r1 = unicode.SimpleFold(r1) {
					re1.Rune = append(re1.Rune, r1, r1)
				}
				info = analyze(re1)
				return info
			}
			// Multi-letter case-folded string:
			// treat as concatenation of single-letter case-folded strings.
			re1 := &syntax.Regexp{
				Op:    syntax.OpLiteral,
				Flags: syntax.FoldCase,
			}
			info = emptyString()
			for i := range re.Rune {
				re1.Rune = re.Rune[i : i+1]
				info = concat(info, analyze(re1))
			}
			return info
		}
		info.exact = stringSet{string(re.Rune)}

	case syntax.OpAnyCharNotNL, syntax.OpAnyChar:
		return anyChar()

	case syntax.OpCapture:
		return analyze(re.Sub[0])

	case syntax.OpConcat:
		return fold(concat, re.Sub, emptyString())

	case syntax.OpAlternate:
		return fold(alternate, re.Sub, noMatch())

	case syntax.OpQuest:
		return alternate(analyze(re.Sub[0]), emptyString())

	case syntax.OpStar:
		// We don't know anything, so assume the worst.
		return anyMatch()

	case syntax.OpRepeat:
		if re.Min == 0 {
			// Like OpStar
			return anyMatch()
		}
		fallthrough
	case syntax.OpPlus:
		// x+
		// Since there has to be at least one x, the prefixes and suffixes
		// stay the same.  If x was exact, it isn't anymore.
		info = analyze(re.Sub[0])
		if info.exact.have() {
			info.prefix = info.exact
			info.suffix = info.exact.copy()
			info.exact = nil
		}

	case syntax.OpCharClass:
		// Special case.
		if len(re.Rune) == 0 {
			return noMatch()
		}

		// Special case.
		if len(re.Rune) == 1 {
			info.exact = stringSet{string(re.Rune[0])}
			break
		}

		n := 0
		for i := 0; i < len(re.Rune); i += 2 {
			n += int(re.Rune[i+1] - re.Rune[i])
		}
		// If the class is too large, it's okay to overestimate.
		if n > 100 {
			return anyChar()
		}

		info.exact = []string{}
		for i := 0; i < len(re.Rune); i += 2 {
			lo, hi := re.Rune[i], re.Rune[i+1]
			for rr := lo; rr <= hi; rr++ {
				info.exact.add(string(rr))
			}
		}
	}

	info.simplify(false)
	return info
}

// fold is the usual higher-order function.
func fold(f func(x, y regexpInfo) regexpInfo, sub []*syntax.Regexp, zero regexpInfo) regexpInfo {
	if len(sub) == 0 {
		return zero
	}
	if len(sub) == 1 {
		return analyze(sub[0])
	}
	info := f(analyze(sub[0]), analyze(sub[1]))
	for i := 2; i < len(sub); i++ {
		info = f(info, analyze(sub[i]))
	}
	return info
}

// concat returns the regexp info for xy given x and y.
func concat(x, y regexpInfo) (out regexpInfo) {
	var xy regexpInfo

	if x.exact.have() && y.exact.have() {
		xy.exact = x.exact.cross(y.exact, false)
	} else {
		if x.exact.have() {
			xy.prefix = x.exact.cross(y.prefix, false)
		} else {
			xy.prefix = x.prefix
			if x.canEmpty {
				xy.prefix = xy.prefix.union(y.prefix, false)
			}
		}
		if y.exact.have() {
			xy.suffix = x.suffix.cross(y.exact, true)
		} else {
			xy.suffix = y.suffix
			if y.canEmpty {
				xy.suffix = xy.suffix.union(x.suffix, true)
			}
		}
	}

	// If all the possible strings in the cross product of x.suffix
	// and y.prefix are long enough, then the trigram for one
	// of them must be present and would not necessarily be
	// accounted for in xy.prefix or xy.suffix yet.  Cut things off
	// at maxSet just to keep the sets manageable.
	if !x.exact.have() && !y.exact.have() &&
		x.suffix.size() <= maxSet && y.prefix.size() <= maxSet &&
		x.suffix.minLen()+y.prefix.minLen() >= 3 {
		xy.internal = x.suffix.cross(y.prefix, false)
	}

	xy.internal = mostDistinctive(xy.internal, x.internal, y.internal)

	xy.simplify(false)
	return xy
}

// alternate returns the regexpInfo for x|y given x and y.
func alternate(x, y regexpInfo) (out regexpInfo) {
	var xy regexpInfo
	if x.exact.have() && y.exact.have() {
		xy.exact = x.exact.union(y.exact, false)
	} else if x.exact.have() {
		xy.prefix = x.exact.union(y.prefix, false)
		xy.suffix = x.exact.union(y.suffix, true)
	} else if y.exact.have() {
		xy.prefix = x.prefix.union(y.exact, false)
		xy.suffix = x.suffix.union(y.exact.copy(), true)
	} else {
		xy.prefix = x.prefix.union(y.prefix, false)
		xy.suffix = x.suffix.union(y.suffix, true)
	}
	xy.canEmpty = x.canEmpty || y.canEmpty

	if !xy.exact.have() {
		xb := x.bestSet()
		yb := y.bestSet()
		if len(xb) > 0 && len(yb) > 0 {
			xy.internal = xb.union(yb, false)
		}
	}

	xy.simplify(false)
	return xy
}

// simplify simplifies the regexpInfo when the exact set gets too large.
func (info *regexpInfo) simplify(force bool) {
	// If there are now too many exact strings,
	// loop over them, moving
	// the relevant pieces into prefix and suffix.
	info.exact.clean(false)
	if len(info.exact) > maxExact {
		for _, s := range info.exact {
			info.prefix.add(s)
			info.suffix.add(s)
		}
		info.exact = nil
	}

	if !info.exact.have() {
		info.simplifySet(&info.prefix)
		info.simplifySet(&info.suffix)
		info.simplifySet(&info.internal)
	}
}

// simplifySet reduces the size of the given set (either prefix or suffix).
// There is no need to pass around enormous prefix or suffix sets, since
// they will only be used to create trigrams.  As they get too big, simplifySet
// moves the information they contain into the match query, which is
// more efficient to pass around.
func (info *regexpInfo) simplifySet(s *stringSet) {
	t := *s
	t.clean(s == &info.suffix)

	n := 0
	for _, str := range t {
		if len(str) > n {
			n = len(str)
		}
	}

	for ; t.size() > maxSet; n-- {
		// Replace set by strings of length n-1.
		w := 0
		for _, str := range t {
			if len(str) >= n {
				if s == &info.prefix {
					str = str[:n-1]
				} else {
					str = str[len(str)-n+1:]
				}
			}
			if w == 0 || t[w-1] != str {
				t[w] = str
				w++
			}
		}
		t = t[:w]
		t.clean(s == &info.suffix)
	}

	// Now make sure that the prefix/suffix sets aren't redundant.
	// For example, if we know "ab" is a possible prefix, then it
	// doesn't help at all to know that  "abc" is also a possible
	// prefix, so delete "abc".
	w := 0
	f := strings.HasPrefix
	if s == &info.suffix {
		f = strings.HasSuffix
	}
	for _, str := range t {
		if w == 0 || !f(str, t[w-1]) {
			t[w] = str
			w++
		}
	}
	t = t[:w]

	*s = t
}

func (info regexpInfo) String() string {
	s := ""
	if info.canEmpty {
		s += "canempty "
	}
	if info.exact.have() {
		s += "exact:" + strings.Join(info.exact, ",")
	} else {
		s += "prefix:" + strings.Join(info.prefix, ",")
		s += " suffix:" + strings.Join(info.suffix, ",")
	}
	//s += " match: " + info.match.String()
	return s
}

// mostDistinctive returns the most distinctive stringSet in sets.
// The most distinctive set is the one that has the longest minLen.
func mostDistinctive(sets ...stringSet) stringSet {
	best := stringSet(nil)
	bestLen := 0

	for _, s := range sets {
		if !s.have() {
			continue
		}
		thisLen := s.minLen()
		if thisLen > bestLen {
			best, bestLen = s, thisLen
		}
	}

	return best
}

// bestSet returns the most distinctive set of strings in info.
func (info regexpInfo) bestSet() stringSet {
	if info.exact.have() {
		return info.exact
	}

	return mostDistinctive(info.prefix, info.suffix, info.internal)
}

// A stringSet is a set of strings.
// The nil stringSet indicates not having a set.
// The non-nil but empty stringSet is the empty set.
type stringSet []string

// have reports whether we have a stringSet.
func (s stringSet) have() bool {
	return s != nil
}

// contains reports whether s contains str.
func (s stringSet) contains(str string) bool {
	for _, ss := range s {
		if ss == str {
			return true
		}
	}
	return false
}

type byPrefix []string

func (x *byPrefix) Len() int           { return len(*x) }
func (x *byPrefix) Swap(i, j int)      { (*x)[i], (*x)[j] = (*x)[j], (*x)[i] }
func (x *byPrefix) Less(i, j int) bool { return (*x)[i] < (*x)[j] }

type bySuffix []string

func (x *bySuffix) Len() int      { return len(*x) }
func (x *bySuffix) Swap(i, j int) { (*x)[i], (*x)[j] = (*x)[j], (*x)[i] }
func (x *bySuffix) Less(i, j int) bool {
	s := (*x)[i]
	t := (*x)[j]
	for i := 1; i <= len(s) && i <= len(t); i++ {
		si := s[len(s)-i]
		ti := t[len(t)-i]
		if si < ti {
			return true
		}
		if si > ti {
			return false
		}
	}
	return len(s) < len(t)
}

// add adds str to the set.
func (s *stringSet) add(str string) {
	*s = append(*s, str)
}

// clean removes duplicates from the stringSet.
func (s *stringSet) clean(isSuffix bool) {
	t := *s
	if isSuffix {
		sort.Sort((*bySuffix)(s))
	} else {
		sort.Sort((*byPrefix)(s))
	}
	w := 0
	for _, str := range t {
		if w == 0 || t[w-1] != str {
			t[w] = str
			w++
		}
	}
	*s = t[:w]
}

// size returns the number of strings in s.
func (s stringSet) size() int {
	return len(s)
}

// minLen returns the length of the shortest string in s.
func (s stringSet) minLen() int {
	if len(s) == 0 {
		return 0
	}
	m := len(s[0])
	for _, str := range s {
		if m > len(str) {
			m = len(str)
		}
	}
	return m
}

// maxLen returns the length of the longest string in s.
func (s stringSet) maxLen() int {
	if len(s) == 0 {
		return 0
	}
	m := len(s[0])
	for _, str := range s {
		if m < len(str) {
			m = len(str)
		}
	}
	return m
}

// union returns the union of s and t, reusing s's storage.
func (s stringSet) union(t stringSet, isSuffix bool) stringSet {
	s = append(s, t...)
	s.clean(isSuffix)
	return s
}

// cross returns the cross product of s and t.
func (s stringSet) cross(t stringSet, isSuffix bool) stringSet {
	p := stringSet{}
	for _, ss := range s {
		for _, tt := range t {
			p.add(ss + tt)
		}
	}
	p.clean(isSuffix)
	return p
}

// clear empties the set but preserves the storage.
func (s *stringSet) clear() {
	*s = (*s)[:0]
}

// copy returns a copy of the set that does not share storage with the original.
func (s stringSet) copy() stringSet {
	return append(stringSet{}, s...)
}

// isSubsetOf returns true if all strings in s are also in t.
// It assumes both sets are sorted.
func (s stringSet) isSubsetOf(t stringSet) bool {
	j := 0
	for _, ss := range s {
		for j < len(t) && t[j] < ss {
			j++
		}
		if j >= len(t) || t[j] != ss {
			return false
		}
	}
	return true
}
