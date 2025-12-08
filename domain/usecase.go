package domain

import (
	"time"

	"github.com/hurtki/jwt/repo"
)

type UserActionHook func(user_id int)
type UserLoginFunc func(username, password string) (user_id int, err error)

func NoopUserActionHook(user_id int) {}

type UseCase struct {
	repo            authRepo
	onLoginHook     UserActionHook
	onLogoutHook    UserActionHook
	userLoginFunc   UserLoginFunc
	TokenExpireTime time.Duration
	secretAppKey    []byte
}

// TODO: add dynamic fields as map to add endpoing to add other information to payload and througing it further ( middleware )
type jwtPayload struct {
	UserID  int       `json:"user_id"`
	Expires time.Time `json:"exp"`
}

type authRepo interface {
	AddRefreshToken(userId int, tokenB64Hash string, expriesAt time.Time) error
	RevokeToken(tokenB64Hash string) error
	RevokeAllFromUser(userID int) error
}

func NewUseCase(repo *repo.PgRepository, userLoginFunc UserLoginFunc, onLoginHook UserActionHook, onLogoutHook UserActionHook) (*UseCase, error) {
	useCase := &UseCase{repo: repo, onLoginHook: onLoginHook, onLogoutHook: onLogoutHook, userLoginFunc: userLoginFunc}

	if onLoginHook == nil {
		useCase.onLoginHook = NoopUserActionHook
	}
	if onLogoutHook == nil {
		useCase.onLogoutHook = NoopUserActionHook
	}
	return useCase, nil
}

func (u *UseCase) Login(username, password string) (TokenPair, error) {
	userId, err := u.userLoginFunc(username, password)
	if err != nil {
		// TODO: create some logic to handle errors from userLogincFunc
		return TokenPair{}, ErrCannotAuthorizeUser
	}

	payload := jwtPayload{UserID: userId, Expires: time.Now().Add(u.TokenExpireTime)}

	accessToken := SignJwtToken(NewHs256JwtHeader(), payload, u.secretAppKey)
	refreshToken := GenNewRefreshToken()

	refreshTokenHash := HashB64(refreshToken)

	err = u.repo.AddRefreshToken(userId, refreshTokenHash, payload.Expires)

	if err != nil {
		// repo error handling
	}

	return TokenPair{Access: accessToken, Refresh: refreshToken}, nil
}

func (u *UseCase) Logout(refreshToken string) error {
	err := u.repo.RevokeToken(refreshToken)
	if err != nil {
		// repo error handling
	}
	return nil
}

func (u *UseCase) Refresh(token string) (AccessToken, error) {
	return "", nil
}
