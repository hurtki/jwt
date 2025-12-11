# jwt

Auth middleware module on jwt tokens

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
