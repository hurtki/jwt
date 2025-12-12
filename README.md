# jwt - Auth module on jwt tokens

![logo](https://raw.githubusercontent.com/hurtki/jwt/e870a87f7a35cd8299f8132b2b65a297cbd2ea2d/_0c406445-2e41-40c6-a03c-c9cdfd02c7b3.jpeg)

## Fast overview

> jwt module was created to fastly connect to **any** service, easy, fast and plain.
> Module takes only postgres db ( other storages will come later ) and **your implementaion** of auth func. You can give for example your usecase method, all in your hands.

## Endpoints

- Login handler
- Refresh handler
- Logout handler
- Authorization Middleware
- Invalidate hook ( WIP )
- OnLogin, OnLogout hooks options

## Fast Start

```
go get "github.com/hurtki/jwt"
```

## Example

```go
db := // db intialization
userRepo := NewUserRepo(db)

usecase := NewUseCase(userRepo, hooks)
tasksHandler := NewTasksHandler(usecase)

secretKey := "n2345njfre..."
auth := jwt.NewAuth(db, userRepo.Authorize, jwt.NewConfig(secretKey))

rtr.Handle("/login", auth.LoginHandler)
rtr.Handle("/refresh", auth.RefreshHandler)
rtr.Handle("/logout", auth.LogoutHandler)
rtr.Handle("/tasks", auth.WithAuth(tasks.Handler))
```

## API

```md
## Login

req: {"username":"root","password":"qwerty1234"}
res 200: {"access":"eyJ...","refresh":"0oUL..."}

## Refresh

req: {"token":"refresh_token"}
res 200: {"token":"access_token"}

## Logout

req: {"token":"refresh_token"}
res 204: No Content

## Middleware

Authorization: Bearer [access_token]
→ next handler / 401 if invalid
```

## Config

**Secret key is used to sign jwt token, if it will change, all previous tokens will become invalid!**

How to configure:

```go
cfg := jwt.NewConfig("your secret key")

// how much time will access token live after signing ( default 15 minutes )
cfg.AccessTokenExpireTime = 15 * time.Minute
// how much time will refresh token live after signing ( default 7 days )
cfg.RefreshTokenExpireTime = time.Hour * 24 * 7
// hooks should be with func(userId int) signature
// On login hook, module will call it after success login ( default Noop )
cfg.OnLogin = yourUseCase.OnLoginHook // example usage
// On logout hook, module will call it after success logout ( default Noop )
cfg.OnLogout = yourUseCase.OnLogoutHook // example usage
// name of key, that module will insert in context for WithAuth middleware handlers ( default "user_id" )
cfg.UserIdContextKeyName = "user_id"

auth := jwt.NewAuth(db, userRepo.Authorize, cfg)
```
