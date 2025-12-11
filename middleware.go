package jwt

import (
	"context"
	"net/http"
	"strings"

	"github.com/hurtki/jwt/domain"
)

func (a *Auth) WithAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := getTokenFromHeader(r)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}

		userId, err := a.usecase.Authorize(token)
		if err != nil {
			switch err {
			case domain.ErrExpiredAccessToken:
				writeJSONError(w, http.StatusUnauthorized, err.Error())
				return
			case domain.ErrInvalidJWT:
				writeJSONError(w, http.StatusBadRequest, err.Error())
				return
			default:
				writeJSONError(w, http.StatusInternalServerError, "can't authorize with token")
				return
			}
		}
		ctx := context.WithValue(r.Context(), a.config.UserIdContextKeyName, userId)
		r = r.WithContext(ctx)
		next(w, r)
	}
}

func getTokenFromHeader(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", errAuthorizationHeaderMissing
	}

	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) {
		return "", errInvalidAuthorizationHeader
	}

	token := strings.TrimPrefix(authHeader, prefix)
	token = strings.TrimSpace(token)
	if token == "" {
		return "", errTokenIsEmpty
	}

	return token, nil
}
