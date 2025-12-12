package jwt

import "errors"

var (
	// errors that handlers or middleware can return ( readable )
	errCannotDeserializeRequest   = errors.New("cannot deserialize request")
	errCannotSerializeResponse    = errors.New("can't serialize response")
	errAuthorizationHeaderMissing = errors.New("Authorization header missing")
	errInvalidAuthorizationHeader = errors.New("Invalid authorization header")
	errTokenIsEmpty               = errors.New("Token is empty")
)
