# jwt

Auth middleware module on jwt tokens

## Endpoints

- login handler
- logout handler
- authorization MiddleWare
- Invalidate hook
- OnLogin, OnLogout hooks options

## Example

```go
db := // db intialization
userRepo := NewUserRepo(db)
authRepo = NewAuthRepo(db)


hooks := NewHooks(logger)
usecase := NewUseCase(userRepo, hooks)
tasksHandler := NewTasksHandler(usecase)

authHooks := jwt.AuthHooks{OnLogin: hooks.OnLogin, OnLogout: hooks.OnLogout}

auth := jwt.NewAuth(db, userRepo.Authorize, authHooks)

rtr.Handle("/login", auth.LoginHandler)
rtr.Handle("/refresh", auth.RefreshHandler)
rtr.Handle("/logout", auth.LogoutHandlerk)
rtr.Handle("/tasks", auth.MiddleWare(tasks.Handler))
```
