package main

// content phrase matching, using the Aho-Corasick algorithm

func init() {
	phraseTrie[0].children = make([]int, 256)
}

// A phraseNode is a node in the trie for scanning for phrases.
type phraseNode struct {
	match    rule  // the phrase rule matched at this point, if any
	children []int // array indexes to continue searching at (256 elements, one for each possible next byte)

	// fallback is the index of the phraseNode that has the longest suffix in common with this node.
	// It is set by findFallbackNodes.
	fallback int
}

// The phraseTrie is a trie of phrase rules.
// It acts as a state table for the state machines that scan the page content.
// It is a byte-by-byte trie in UTF-8 encoding.
var phraseTrie = make([]phraseNode, 1, 1000)

// addPhrase adds a phrase to the phraseTrie.
func addPhrase(p rule) {
	s := p.content
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

// findFallbackNodes traverses the phrase trie and sets each node's fallback
// pointer. node is the node to use as the root of the search,
// and text is the bytes that would take the scanner there from the root of the
// trie. For the root node, node == 0 and text == nil.
func findFallbackNodes(node int, text []byte) {
	// Find this node's fallback node.
	for i := 1; i < len(text); i++ {
		f := 0 // If there is no suffix in common, use the root.
		for j := i; j < len(text); j++ {
			ch := phraseTrie[f].children
			if ch == nil {
				break
			}
			f = ch[text[j]]
			if f == 0 {
				break
			}
		}
		if f != 0 {
			phraseTrie[node].fallback = f
			break
		}
	}

	// Traverse this node's children.
	for c, n := range phraseTrie[node].children {
		if n != 0 {
			findFallbackNodes(n, append(text, byte(c)))
		}
	}
}

// A phraseScanner scans input one byte at a time
// and counts occurrences of phrases.
type phraseScanner struct {
	state int          // the current node in the phraseTrie
	tally map[rule]int // the counts of the phrases
}

func newPhraseScanner() *phraseScanner {
	return &phraseScanner{tally: make(map[rule]int)}
}

// scanByte updates ps for one byte of input.
func (ps *phraseScanner) scanByte(c byte) {
	// Find the new state.
	state := ps.state
	newState := 0

	if ch := phraseTrie[state].children; ch != nil {
		newState = ch[c]
	}
	for newState == 0 && state != 0 {
		state = phraseTrie[state].fallback
		if ch := phraseTrie[state].children; ch != nil {
			newState = ch[c]
		}
	}
	ps.state = newState

	// See if any phrases have been matched.
	for n := newState; n != 0; n = phraseTrie[n].fallback {
		if m := phraseTrie[n].match; m.t != defaultRule {
			ps.tally[m]++
		}
	}
}
