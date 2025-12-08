package jwt

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type refreshRequest struct {
	Token string `json:"token"`
}

type logoutRequest struct {
	Token string `json:"token"`
}

type loginResponse struct {
	Access  string `json:"access"`
	Refresh string `json:"refresh"`
}

type refreshResponse struct {
	Token string `json:"token"`
}
