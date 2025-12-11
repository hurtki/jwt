package domain

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
)

var (
	tokenType = "jwt"
	algHs256  = "hs256"
)

type jwtHeader struct {
	Algorithm string `json:"alg"`
	TokenType string `json:"typ"`
}

func NewHs256JwtHeader() jwtHeader {
	return jwtHeader{
		Algorithm: algHs256,
		TokenType: tokenType,
	}
}

func b64Encode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func b64Decode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func signHS256(msg, secret []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write(msg)
	return mac.Sum(nil)
}

func SignJwtToken(header jwtHeader, payload any, secret []byte) string {
	h, _ := json.Marshal(header)

	p, _ := json.Marshal(payload)

	hEnc := b64Encode(h)
	pEnc := b64Encode(p)

	msg := []byte(hEnc + "." + pEnc)

	sig := signHS256(msg, secret)
	sEnc := b64Encode(sig)

	return hEnc + "." + pEnc + "." + sEnc
}

func ParseAndVerifyJwt(
	token string,
	secret []byte,
	payloadOut any) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ErrInvalidJWT
	}

	hEnc, pEnc, sEnc := parts[0], parts[1], parts[2]

	// checking token's headers

	headersDecoded, err := b64Decode(hEnc)
	if err != nil {
		return ErrInvalidJWT
	}

	jwtHeader := jwtHeader{}

	if err := json.Unmarshal(headersDecoded, &jwtHeader); err != nil {
		return ErrInvalidJWT
	}

	if jwtHeader.TokenType != "jwt" {
		return ErrInvalidJWT
	}

	if jwtHeader.Algorithm != algHs256 {
		return ErrInvalidJWT
	}

	// checking token sign
	switch jwtHeader.Algorithm {
	case algHs256:
		msg := []byte(hEnc + "." + pEnc)
		if b64Encode(signHS256(msg, secret)) != sEnc {
			return ErrInvalidJWT
		}

		// decoding + unmarshaling payload
		payloadDecoded, err := b64Decode(pEnc)
		if err != nil {
			return ErrInvalidJWT
		}

		err = json.Unmarshal(payloadDecoded, payloadOut)
		if err != nil {
			return ErrInvalidJWT
		}

		return nil
	}

	return ErrInvalidJWT
}
