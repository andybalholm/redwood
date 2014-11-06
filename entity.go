package main

import (
	"golang.org/x/net/html"
	"golang.org/x/text/transform"
)

// An entityDecoder is a Transformer that decodes HTML character entities.
type entityDecoder struct{}

func (entityDecoder) Transform(dst, src []byte, atEOF bool) (nDst, nSrc int, err error) {
	for nSrc < len(src) && nDst < len(dst) {
		if c := src[nSrc]; c != '&' {
			dst[nDst] = c
			nSrc++
			nDst++
			continue
		}

		// Try to decode a character entity.
		entityLen := 1
		for entityLen < 32 {
			if nSrc+entityLen == len(src) {
				if atEOF {
					break
				} else {
					err = transform.ErrShortSrc
					return
				}
			}
			if b := src[nSrc+entityLen]; 'a' <= b && b <= 'z' || 'A' <= b && b <= 'Z' || '0' <= b && b <= '9' || entityLen == 1 && b == '#' || b == ';' {
				entityLen++
				if b == ';' {
					break
				}
			} else {
				break
			}
		}

		e := string(src[nSrc : nSrc+entityLen])
		decoded := html.UnescapeString(e)
		n := copy(dst[nDst:], decoded)
		if n < len(decoded) {
			err = transform.ErrShortDst
			return
		}
		nSrc += entityLen
		nDst += len(decoded)
	}

	if nSrc < len(src) && err == nil {
		err = transform.ErrShortDst
	}
	return
}

func (entityDecoder) Reset() {
}
