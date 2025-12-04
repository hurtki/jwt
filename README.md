# jwt

Auth middleware module on jwt tokens

## Endpoints

- login handler
- logout handler
- authorization MiddleWare
- OnLogin, OnLogout hooks

## Example

```go
db := // db intialization
userRepo := NewUserRepo(db)
authRepo = NewAuthRepo(db)


hooks := NewHooks(logger)
usecase := NewUseCase(userRepo, hooks)
tasksHandler := NewTasksHandler(usecase)

auth := jwt.NewAuth(db, userRepo.Authorize, hooks.OnLogin, hooks.OnLogout)

rtr.Handle("/login", auth.LoginHandler)
rtr.Handle("/refresh", auth.RefreshHandler)
rtr.Handle("/logout", auth.LogoutHandlerk)
rtr.Handle("/tasks", auth.MiddleWare(tasks.Handler))
```
