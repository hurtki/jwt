package domain

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

const (
	refreshTokenLength = 64
)

func RandBase64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func GenNewRefreshToken() string {
	return RandBase64(refreshTokenLength)
}

func HashB64(token string) string {
	sum := sha256.Sum256([]byte(token))
	return b64Encode(sum[:])
}
