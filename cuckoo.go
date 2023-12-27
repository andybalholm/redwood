package main

import (
	"math/rand"

	"github.com/zeebo/xxh3"
)

type bucket [4]uint16

// A CuckooFilter represents a set of strings. This implementation uses 16-bit
// fingerprints, so its false positive rate should be about 1 in 8000.
type CuckooFilter struct {
	buckets    []bucket
	mask       int
	bucketBits int
	rand       *rand.Rand
}

func NewCuckooFilter(n int) *CuckooFilter {
	minSize := int(float64(n) / 4 * 1.05)
	size := 1
	bits := 0
	for size < minSize {
		size <<= 1
		bits++
	}
	return &CuckooFilter{
		buckets:    make([]bucket, size),
		mask:       size - 1,
		bucketBits: bits,
		rand:       rand.New(rand.NewSource(rand.Int63())),
	}
}

func (f *CuckooFilter) indexAndFingerprint(s string) (int, uint16) {
	hash := xxh3.HashString(s)
	fingerprint := uint16(hash >> 48)
	if fingerprint == 0 {
		fingerprint = 1
	}
	return int(hash) & f.mask, fingerprint
}

const hashMul32 = 0x1e35a7bd

func (f *CuckooFilter) altIndex(fingerprint uint16, i int) int {
	hash := uint32(fingerprint) * hashMul32
	return int(hash>>(32-f.bucketBits)) ^ i
}

func (f *CuckooFilter) insert(fp uint16, i int) bool {
	b := &f.buckets[i]
	for j := range b {
		if b[j] == 0 {
			b[j] = fp
			return true
		}
	}
	return false
}

func (f *CuckooFilter) Insert(s string) bool {
	i, fp := f.indexAndFingerprint(s)
	if f.insert(fp, i) {
		return true
	}
	i2 := f.altIndex(fp, i)
	if f.insert(fp, i2) {
		return true
	}
	if f.rand.Intn(2) == 1 {
		i = i2
	}
	for k := 0; k < 500; k++ {
		j := f.rand.Intn(4)
		f.buckets[i][j], fp = fp, f.buckets[i][j]
		i = f.altIndex(fp, i)
		if f.insert(fp, i) {
			return true
		}
	}
	return false
}

func (f *CuckooFilter) contains(fp uint16, i int) bool {
	b := &f.buckets[i]
	for j := range b {
		if b[j] == fp {
			return true
		}
	}
	return false
}

func (f *CuckooFilter) Contains(s string) bool {
	i, fp := f.indexAndFingerprint(s)
	if f.contains(fp, i) {
		return true
	}
	i2 := f.altIndex(fp, i)
	return f.contains(fp, i2)
}
