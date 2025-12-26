package domain

import (
	"time"

	"github.com/hurtki/jwt/config"
	"github.com/hurtki/jwt/internal/adapters"
	"github.com/hurtki/jwt/internal/repo"
	"github.com/hurtki/jwt/internal/wrappers"
)

type AuthFunc func(wrappers.AuthInputWrapper) (wrappers.PayloadWrapper, error)

func NoopHook(user_id int) {}

// domain level of clean architechture
// uses repo interface and maps repo errors into domain
type UseCase struct {
	repo     authRepo
	authFunc AuthFunc
	cfg      config.AuthConfig
	adapter  adapters.UseCaseAdapter
}

type authRepo interface {
	AddRefreshToken(tokenB64Hash string, expriesAt time.Time) error
	RevokeToken(tokenB64Hash string) (err error)
	CheckToken(tokenB64Hash string) (err error)
}

func NewUseCase(repo authRepo, authFunc AuthFunc, config config.AuthConfig) *UseCase {
	return &UseCase{repo: repo, cfg: config, authFunc: authFunc}
}

func (u *UseCase) Login(authInput wrappers.AuthInputWrapper) (TokenPair, error) {
	payload, err := u.authFunc(authInput)
	if err != nil {
		// TODO: create some logic to handle errors from userLogincFunc
		return TokenPair{}, ErrCannotAuthorizeUser
	}

	payload.ExpireAt = time.Now().Add(u.cfg.AccessTokenExpireTime)

	accessToken := SignJwtToken(NewHs256JwtHeader(), payload, u.cfg.AppSecretKey)
	refreshToken := GenNewRefreshToken()

	refreshTokenHash := HashB64(refreshToken)

	err = u.repo.AddRefreshToken(refreshTokenHash, time.Now().Add(u.cfg.RefreshTokenExpireTime))

	if err != nil {
		return TokenPair{}, ErrCannotAuthorizeUser
	}

	u.adapter.HookWrapper.Call(payload)

	return TokenPair{Access: accessToken, Refresh: refreshToken}, nil
}

func (u *UseCase) Refresh(token string) (AccessToken, error) {
	refreshTokenHash := HashB64(token)

	userId, err := u.repo.CheckToken(refreshTokenHash)

	if err != nil {
		if err == repo.ErrNothingFound {
			return AccessToken(""), ErrInvalidRefreshToken
		}
		return AccessToken(""), ErrCannotRefreshToken
	}

	payload := jwtPayload{UserID: userId, Expires: time.Now().Add(u.cfg.AccessTokenExpireTime)}

	accessToken := SignJwtToken(NewHs256JwtHeader(), payload, u.cfg.AppSecretKey)

	return AccessToken(accessToken), nil
}

func (u *UseCase) Logout(refreshToken string) error {
	refreshTokenHash := HashB64(refreshToken)

	userId, err := u.repo.RevokeToken(refreshTokenHash)

	if err != nil {
		if err == repo.ErrNothingChanged {
			return ErrInvalidRefreshToken
		} else {
			return ErrCannotRevokeToken
		}
	}

	u.cfg.OnLogout(userId)

	return nil
}

func (u *UseCase) Authorize(accessToken string) (userId int, err error) {
	payload := jwtPayload{}
	err = ParseAndVerifyJwt(accessToken, u.cfg.AppSecretKey, &payload)
	if err != nil {
		return 0, err
	}

	if payload.Expires.Before(time.Now()) {
		return 0, ErrExpiredAccessToken
	}

	return payload.UserID, nil
}
