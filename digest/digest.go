package digest

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"fmt"
	"hash"
	"net/http"
	"strings"
)

type DigestAlgorithm string

const (
	DigestSha256 DigestAlgorithm = "SHA-256"
	DigestSha512                 = "SHA-512"
)

// String method for DigestAlgorithm
func (d DigestAlgorithm) String() string {
	return string(d)
}

var digestToDef = map[DigestAlgorithm]crypto.Hash{
	DigestSha256: crypto.SHA256,
	DigestSha512: crypto.SHA512,
}

// IsSupportedDigestAlgorithm returns true if hte string is supported by this
// library, is not a hash known to be weak, and is supported by the hardware.
func IsSupportedDigestAlgorithm(algo string) bool {
	uc := DigestAlgorithm(strings.ToUpper(algo))
	c, ok := digestToDef[uc]
	return ok && c.Available()
}

func getHash(alg DigestAlgorithm) (h hash.Hash, toUse DigestAlgorithm, err error) {
	upper := DigestAlgorithm(strings.ToUpper(string(alg)))
	c, ok := digestToDef[upper]
	if !ok {
		err = fmt.Errorf("unknown or unsupported Digest algorithm: %s", alg)
	} else if !c.Available() {
		err = fmt.Errorf("unavailable Digest algorithm: %s", alg)
	} else {
		h = c.New()
		toUse = upper
	}
	return
}

const (
	digestHeader = "content-digest"
	digestDelim  = "="
)

// AddDigest computes a digest of the given request body `b` using the specified 
// hashing algorithm `algo` and adds it to the `Digest` header of the HTTP request `r`.
// The digest is Base64-encoded, with padding controlled by the optional `withPadding` argument.
// If `withPadding` is not provided, the default is to use padding.
func AddDigest(r *http.Request, algo DigestAlgorithm, b []byte, withPadding ...bool) (err error) {
	dh := r.Header.Get(digestHeader)
	if dh != "" {
		err = fmt.Errorf("cannot add Digest: Digest is already set")
		return
	}
	var h hash.Hash
	var a DigestAlgorithm
	h, a, err = getHash(algo)
	if err != nil {
		return
	}
	h.Write(b)
	sum := h.Sum(nil)
	// Determine whether to use padding
	usePadding := true
	if len(withPadding) > 0 {
	    usePadding = withPadding[0]
	}
	var edig string
	if usePadding {
	    edig = base64.URLEncoding.EncodeToString(sum[:]) // Padded Base64
	} else {
	    edig = base64.RawURLEncoding.EncodeToString(sum[:]) // Unpadded Base64
	}
	r.Header.Add(digestHeader,
		fmt.Sprintf("%s%s:%s:",
			strings.ToLower(string(a)),
			digestDelim,
			edig))
	return
}

func AddDigestResponse(r http.ResponseWriter, algo DigestAlgorithm, b []byte, withPadding ...bool) (err error) {
	_, ok := r.Header()[digestHeader]
	if ok {
		err = fmt.Errorf("cannot add Digest: Digest is already set")
		return
	}
	var h hash.Hash
	var a DigestAlgorithm
	h, a, err = getHash(algo)
	if err != nil {
		return
	}
	h.Write(b)
	sum := h.Sum(nil)
	// Determine whether to use padding
	usePadding := true
	if len(withPadding) > 0 {
	    usePadding = withPadding[0]
	}
	var edig string
	if usePadding {
	    edig = base64.URLEncoding.EncodeToString(sum[:]) // Padded Base64
	} else {
	    edig = base64.RawURLEncoding.EncodeToString(sum[:]) // Unpadded Base64
	}
	r.Header().Add(digestHeader,
		fmt.Sprintf("%s%s%s",
			a,
			digestDelim,
			edig))
	return
}

func verifyDigest(r *http.Request, body *bytes.Buffer, withPadding ...bool) (err error) {
	d := r.Header.Get(digestHeader)
	if len(d) == 0 {
		err = fmt.Errorf("cannot verify Digest: request has no Digest header")
		return
	}
	elem := strings.SplitN(d, digestDelim, 2)
	if len(elem) != 2 {
		err = fmt.Errorf("cannot verify Digest: malformed Digest: %s", d)
		return
	}
	var h hash.Hash
	h, _, err = getHash(DigestAlgorithm(elem[0]))
	if err != nil {
		return
	}
	h.Write(body.Bytes())
	sum := h.Sum(nil)
	// Determine whether to use padding
	usePadding := true
	if len(withPadding) > 0 {
	    usePadding = withPadding[0]
	}
	var encSum string
	if usePadding {
	    encSum = fmt.Sprintf(":%s:", base64.URLEncoding.EncodeToString(sum[:])) // Padded Base64
	} else {
	    encSum = fmt.Sprintf(":%s:", base64.RawURLEncoding.EncodeToString(sum[:])) // Unpadded Base64
	}
	fmt.Printf("\n")
	fmt.Printf("encSum: %s elem1: %s", encSum, elem[1])
	if encSum != elem[1] {
		err = fmt.Errorf("cannot verify Digest: header Digest does not match the digest of the request body")
		return
	}
	return
}
