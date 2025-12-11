package config

import "time"

// signature for external function that auth will use as hooks
type Hook func(userId int)

type AuthConfig struct {
	// secret for signing jwt tokens
	AppSecretKey []byte
	// how much time access token lives
	AccessTokenExpireTime time.Duration
	// how much time refresh token lives
	RefreshTokenExpireTime time.Duration

	// hook that will be used after success login
	OnLogin Hook
	// hook that will be used after success logout
	OnLogout Hook

	// name of key that will be inserted into ctx, for handlers that use WithAuth middleware
	UserIdContextKeyName string
}
