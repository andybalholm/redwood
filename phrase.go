package main

// content phrase matching, using the Aho-Corasick algorithm

// A phraseNode is a node in the trie for scanning for phrases.
type phraseNode struct {
	match    string  // the phrase matched at this point, if any
	children []int32 // array indexes to continue searching at (128 or 256 elements, one for each possible next byte)

	// onlyChild is used instead of children if it would contain only one
	// nonzero entry.
	onlyChild     int32
	onlyChildByte byte

	// fallback is the index of the phraseNode that has the longest suffix in common with this node.
	// It is set by findFallbackNodes.
	fallback int32
}

// child returns the index of the node to transition to if the next byte is b.
func (n *phraseNode) child(b byte) int32 {
	if int(b) < len(n.children) {
		return n.children[b]
	}
	if b == n.onlyChildByte {
		return n.onlyChild
	}
	return 0
}

// setChild sets the index to transition to when the byte read is b.
func (n *phraseNode) setChild(b byte, next int32) {
	if int(b) < len(n.children) {
		n.children[b] = next
		return
	}
	if n.children != nil {
		// children has only 128 elements, and b is a high-bit byte.
		newChildren := make([]int32, 256)
		copy(newChildren, n.children)
		n.children = newChildren
		n.children[b] = next
		return
	}
	if n.onlyChild == 0 {
		n.onlyChild = next
		n.onlyChildByte = b
		return
	}
	if b < 128 && n.onlyChildByte < 128 {
		n.children = make([]int32, 128)
	} else {
		n.children = make([]int32, 256)
	}
	n.children[n.onlyChildByte] = n.onlyChild
	n.children[b] = next
}

// A phraseList is a trie of phrase rules (with fallback pointers for
// Aho-Corasick).
// It acts as a state table for the state machine that scans the page content.
// It is a byte-by-byte trie in UTF-8 encoding.
type phraseList []phraseNode

func newPhraseList() phraseList {
	p := make([]phraseNode, 1, 500)
	return p
}

// addPhrase adds a phrase to p.
func (p *phraseList) addPhrase(s string) {
	n := int32(0) // index into phraseTrie
	for i := 0; i < len(s); i++ {
		c := s[i]
		node := &(*p)[n]
		next := node.child(c)
		if next == 0 {
			next = int32(len(*p))
			node.setChild(c, next)
			*p = append(*p, phraseNode{})
		}
		n = next
	}

	(*p)[n].match = s
}

// findFallbackNodes traverses the phrase trie and sets each node's fallback
// pointer. node is the node to use as the root of the search,
// and text is the bytes that would take the scanner there from the root of the
// trie. For the root node, node == 0 and text == nil.
func (p *phraseList) findFallbackNodes(node int32, text []byte) {
	v := &(*p)[node]
	// Find this node's fallback node.
	for i := 1; i < len(text); i++ {
		f := int32(0) // If there is no suffix in common, use the root.
		for j := i; j < len(text); j++ {
			f = (*p)[f].child(text[j])
			if f == 0 {
				break
			}
		}
		if f != 0 {
			v.fallback = f
			break
		}
	}

	// Traverse this node's children.
	switch {
	case v.children != nil:
		for c, n := range v.children {
			if n != 0 {
				p.findFallbackNodes(n, append(text, byte(c)))
			}
		}
	case v.onlyChild != 0:
		p.findFallbackNodes(v.onlyChild, append(text, v.onlyChildByte))
	}
}

// A phraseScanner scans input one byte at a time
// and calls callback with the matching phrases.
type phraseScanner struct {
	list        phraseList
	currentNode int32 // the current node in the phraseList
	callback    func(string)
}

func newPhraseScanner(list phraseList, callback func(string)) *phraseScanner {
	return &phraseScanner{
		list:     list,
		callback: callback,
	}
}

// scanByte updates ps for one byte of input.
func (ps *phraseScanner) scanByte(c byte) {
	// Find the new current node.
	currentNode := ps.currentNode

	newState := ps.list[currentNode].child(c)
	for currentNode != 0 && newState == 0 {
		currentNode = ps.list[currentNode].fallback
		newState = ps.list[currentNode].child(c)
	}
	ps.currentNode = newState

	// See if any phrases have been matched.
	for n := newState; n != 0; n = ps.list[n].fallback {
		if m := ps.list[n].match; m != "" {
			ps.callback(m)
		}
	}
}
