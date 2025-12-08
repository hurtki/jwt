package domain

import "errors"

var (
	ErrCannotAuthorizeUser = errors.New("cannot authorize user")
	ErrInvalidJWT          = errors.New("invalid jwt")
)
