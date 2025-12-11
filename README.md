# jwt - Auth module on jwt tokens

![logo](https://raw.githubusercontent.com/hurtki/jwt/e870a87f7a35cd8299f8132b2b65a297cbd2ea2d/_0c406445-2e41-40c6-a03c-c9cdfd02c7b3.jpeg)

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
