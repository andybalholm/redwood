package main

// content phrase matching

import (
	"fmt"
)

func init() {
	phraseTrie[0].children = make([]int, 256)
}

// A phraseNode is a node in the trie for scanning for phrases.
type phraseNode struct {
	match    string // the phrase rule (still in angle brackets) matched at this point, if any
	children []int  // array indexes to continue searching at (256 elements, one for each possible next byte)
}

// The phraseTrie is a trie of phrase rules.
// It acts as a state table for the state machines that scan the page content.
// It is a byte-by-byte trie in UTF-8 encoding.
var phraseTrie = make([]phraseNode, 1, 1000)

// addPhrase adds a phrase to the phraseTrie.
// It should still have the angle brackets around it from the config file.
func addPhrase(p string) {
	if len(p) < 2 || p[0] != '<' || p[len(p)-1] != '>' {
		panic(fmt.Errorf(`The phrase "%s" is not in angle brackets.`, p))
	}

	s := p[1 : len(p)-1]
	n := 0 // index into phraseTrie
	for i := 0; i < len(s); i++ {
		if phraseTrie[n].children == nil {
			phraseTrie[n].children = make([]int, 256)
		}
		next := phraseTrie[n].children[s[i]]
		if next == 0 {
			next = len(phraseTrie)
			phraseTrie[n].children[s[i]] = next
			phraseTrie = append(phraseTrie, phraseNode{})
		}
		n = next
	}

	phraseTrie[n].match = p
}

// A phraseScanner scans input one byte at a time
// and counts occurrences of phrases.
type phraseScanner struct {
	states []int          // the state machines to do the scanning
	tally  map[string]int // the counts of the phrases
}

func newPhraseScanner() *phraseScanner {
	return &phraseScanner{tally: make(map[string]int)}
}

// scanByte updates ps for one byte of input.
func (ps *phraseScanner) scanByte(c byte) {
	startedNew := false
	for i, state := range ps.states {
		if state == 0 {
			if startedNew {
				continue // Don't start more than one state machine per byte.
			}
			startedNew = true
		}

		if phraseTrie[state].children == nil {
			ps.states[i] = 0
			continue
		}

		newState := phraseTrie[state].children[c]
		ps.states[i] = newState
		match := phraseTrie[newState].match
		if match != "" {
			ps.tally[match]++
		}
	}

	if !startedNew {
		// Add a new state machine.
		newState := phraseTrie[0].children[c]
		if newState != 0 {
			ps.states = append(ps.states, newState)
		}
		match := phraseTrie[newState].match
		if match != "" {
			ps.tally[match]++
		}
	}
}
