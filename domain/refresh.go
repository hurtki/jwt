package domain

import (
	"crypto/rand"
	"crypto/sha256"
)

const (
	refreshTokenLength = 64 // length of bytes of refresh token on generation
)

// RandBase64 is used to generate random entropy of length n and encode to B64
// used to generate refresh tokens
func RandBase64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b64Encode(b)
}

// GenNewRefreshToken generates new refresh token encoded in B64
func GenNewRefreshToken() string {
	return RandBase64(refreshTokenLength)
}

// HashB64 first takes sha256 hash of token and then encodes it to b64
func HashB64(token string) string {
	sum := sha256.Sum256([]byte(token))
	return b64Encode(sum[:])
}
