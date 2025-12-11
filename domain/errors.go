package domain

import "errors"

var (
	ErrCannotAuthorizeUser = errors.New("cannot authorize user")
	ErrExpiredAccessToken  = errors.New("expired access token")
	ErrInvalidJWT          = errors.New("invalid jwt")
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
	ErrCannotRefreshToken  = errors.New("cannot refresh token")
	ErrCannotRevokeToken   = errors.New("cannot revoke token ")
)
