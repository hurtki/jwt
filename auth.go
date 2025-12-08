package jwt

import (
	"database/sql"
	"errors"

	"github.com/hurtki/jwt/domain"
	"github.com/hurtki/jwt/repo"
)

// Authoorize func is a function/method that Auth recieves as a dependency
// Auth will use to login users on Auth.LoginHandler
type AuthorizeFunc func(username, password string) (user_id int, err error)

// AuthHooks is needed if you want to specify Hooks for Auth.LoginHandler and Auth.Logiut handler
type AuthHooks struct {
	OnLogin  func(user_id int)
	OnLogout func(user_id int)
}

// Module for authorization based on jwt tokens
type Auth struct {
	usecase *domain.UseCase
}

// db - postgres database ( ready connection, module won't change settings of conneciton )
// authFunc - required function to authorize user on Auth.LoginHandler, hooks not required filds( can be bull )
func NewAuth(db *sql.DB, authFunc AuthorizeFunc, hooks AuthHooks) (*Auth, error) {
	repo, err := repo.NewAuthRepo(db)
	if err != nil {
		return nil, err
	}

	if authFunc == nil {
		return nil, errors.New("can't create Auth without authFunc ( authFunc cannot be nil )")
	}

	usecase, err := domain.NewUseCase(repo, domain.UserLoginFunc(authFunc), hooks.OnLogin, hooks.OnLogout)
	return &Auth{usecase: usecase}, nil
}
