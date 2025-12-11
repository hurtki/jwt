package jwt

import (
	"database/sql"
	"errors"
	"time"

	"github.com/hurtki/jwt/config"
	"github.com/hurtki/jwt/domain"
	pg_repo "github.com/hurtki/jwt/repo/pg"
)

// Authoorize func is a function/method that Auth recieves as a dependency
// Auth will use to login users on Auth.LoginHandler
type AuthorizeFunc func(username, password string) (user_id int, err error)

// Module for authorization based on jwt tokens
type Auth struct {
	config  config.AuthConfig
	usecase *domain.UseCase
}

// db - postgres database ( ready connection, module won't change settings of conneciton )
// authFunc - required function to authorize user on Auth.LoginHandler, hooks not required filds( can be bull )
func NewAuth(db *sql.DB, authFunc AuthorizeFunc, config config.AuthConfig) (*Auth, error) {
	repo, err := pg_repo.NewAuthRepo(db)
	if err != nil {
		return nil, err
	}

	if authFunc == nil {
		return nil, errors.New("can't create Auth without authFunc ( authFunc cannot be nil )")
	}

	usecase, err := domain.NewUseCase(repo, domain.UserLoginFunc(authFunc), config)
	return &Auth{usecase: usecase, config: config}, nil
}

func NewConfig(secretKey string) config.AuthConfig {
	return config.AuthConfig{
		AppSecretKey:           []byte(secretKey),
		AccessTokenExpireTime:  time.Minute * 15,
		RefreshTokenExpireTime: time.Hour * 24 * 7,
		OnLogin:                nil,
		OnLogout:               nil,
		UserIdContextKeyName:   "user_id",
	}
}
