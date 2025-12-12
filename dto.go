package jwt

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	Access  string `json:"access_token"`
	Refresh string `json:"refresh_token"`
}

type refreshRequest struct {
	Token string `json:"refresh_token"`
}

type refreshResponse struct {
	Token string `json:"access_token"`
}

type logoutRequest struct {
	Token string `json:"refresh_token"`
}
