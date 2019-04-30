package main

const (
	bloomFilterSize   = 16
	bloomFilterBits   = bloomFilterSize * 64
	bloomFilterHashes = 7

	fnv32Prime  = 16777619
	fnv32Offset = 2166136261
)

type bloomFilter [bloomFilterSize]uint64

// setBit sets one bit of b.
func (b *bloomFilter) setBit(i uint32) {
	word, bit := i/64, i%64
	b[word] |= 1 << bit
}

// Add adds s to the set of strings represented by b.
func (b *bloomFilter) Add(s string) {
	// Calculate FNV-1a hash of s, and set corresponding bit.
	h := uint32(fnv32Offset)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= fnv32Prime
	}
	b.setBit(h % bloomFilterBits)

	// Calculate additional hashes, and set those bits as well.
	for i := 1; i < bloomFilterHashes; i++ {
		h ^= fnv32Offset
		h *= fnv32Prime
		b.setBit(h % bloomFilterBits)
	}
}

// Superset returns whether b is a superset of b2. (False positives are
// possible, since these are bloom filters.)
func (b *bloomFilter) Superset(b2 *bloomFilter) bool {
	for i := range *b {
		if b[i]&b2[i] != b2[i] {
			return false
		}
	}
	return true
}
