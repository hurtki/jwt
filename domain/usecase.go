package domain

import (
	"time"

	"github.com/hurtki/jwt/config"
	"github.com/hurtki/jwt/repo"
)

type UserLoginFunc func(username, password string) (user_id int, err error)

func NoopHook(user_id int) {}

// domain level of clean architechture
// uses repo interface and maps repo errors into domain
type UseCase struct {
	repo          authRepo
	userLoginFunc UserLoginFunc
	cfg           config.AuthConfig
}

// TODO: add dynamic fields as map to add endpoing to add other information to payload and througing it further ( middleware )
type jwtPayload struct {
	UserID  int       `json:"user_id"`
	Expires time.Time `json:"exp"`
}

type authRepo interface {
	AddRefreshToken(userId int, tokenB64Hash string, expriesAt time.Time) error
	RevokeToken(tokenB64Hash string) (userId int, err error)
	//	RevokeAllFromUser(userID int) error
	CheckToken(tokenB64Hash string) (userId int, err error)
}

func NewUseCase(repo authRepo, userLoginFunc UserLoginFunc, config config.AuthConfig) *UseCase {
	useCase := &UseCase{repo: repo, cfg: config, userLoginFunc: userLoginFunc}

	if useCase.cfg.OnLogin == nil {
		useCase.cfg.OnLogin = NoopHook
	}
	if useCase.cfg.OnLogout == nil {
		useCase.cfg.OnLogout = NoopHook
	}
	return useCase
}

func (u *UseCase) Login(username, password string) (TokenPair, error) {
	userId, err := u.userLoginFunc(username, password)
	if err != nil {
		// TODO: create some logic to handle errors from userLogincFunc
		return TokenPair{}, ErrCannotAuthorizeUser
	}

	payload := jwtPayload{UserID: userId, Expires: time.Now().Add(u.cfg.AccessTokenExpireTime)}

	accessToken := SignJwtToken(NewHs256JwtHeader(), payload, u.cfg.AppSecretKey)
	refreshToken := GenNewRefreshToken()

	refreshTokenHash := HashB64(refreshToken)

	err = u.repo.AddRefreshToken(userId, refreshTokenHash, time.Now().Add(u.cfg.RefreshTokenExpireTime))

	if err != nil {
		return TokenPair{}, ErrCannotAuthorizeUser
	}

	u.cfg.OnLogin(userId)

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
