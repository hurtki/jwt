package jwt

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/hurtki/jwt/domain"
)

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	resp := map[string]any{
		"error": msg,
	}

	json.NewEncoder(w).Encode(resp)
}

func parseJSONBody[T any](r *http.Request) (T, error) {
	var dto T
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return dto, err
	}
	err = json.Unmarshal(body, &dto)
	return dto, err
}

func (a *Auth) LoginHandler(res http.ResponseWriter, req *http.Request) {
	reqDto, err := parseJSONBody[loginRequest](req)
	if err != nil {
		writeJSONError(res, http.StatusBadRequest, errCannotDeserializeRequest.Error())
		return
	}

	tokenPair, err := a.usecase.Login(reqDto.Username, reqDto.Password)

	if err != nil {
		if err == domain.ErrCannotAuthorizeUser {
			writeJSONError(res, http.StatusUnauthorized, err.Error())
			return
		} else {
			writeJSONError(res, http.StatusInternalServerError, err.Error())
			return
		}
	}

	resDto := loginResponse{Access: tokenPair.Access, Refresh: tokenPair.Refresh}

	data, err := json.Marshal(resDto)
	if err != nil {
		writeJSONError(res, http.StatusInternalServerError, errCannotSerializeResponse.Error())
		return
	}

	res.WriteHeader(http.StatusOK)
	res.Write(data)
}
func (a *Auth) RefreshHandler(res http.ResponseWriter, req *http.Request) {
	reqDto, err := parseJSONBody[refreshRequest](req)
	if err != nil {
		writeJSONError(res, http.StatusBadRequest, errCannotDeserializeRequest.Error())
		return
	}

	token, err := a.usecase.Refresh(reqDto.Token)

	if err != nil {
		switch err {
		case domain.ErrInvalidRefreshToken:
			writeJSONError(res, http.StatusUnauthorized, err.Error())
			return
		case domain.ErrCannotRefreshToken:
			writeJSONError(res, http.StatusInternalServerError, err.Error())
			return
		default:
			writeJSONError(res, http.StatusInternalServerError, err.Error())
			return
		}
	}

	resDto := refreshResponse{Token: string(token)}

	data, err := json.Marshal(resDto)
	if err != nil {
		writeJSONError(res, http.StatusInternalServerError, errCannotSerializeResponse.Error())
		return
	}

	res.WriteHeader(http.StatusOK)
	res.Write(data)
}

func (a *Auth) LogoutHandler(res http.ResponseWriter, req *http.Request) {
	reqDto, err := parseJSONBody[logoutRequest](req)
	if err != nil {
		writeJSONError(res, http.StatusBadRequest, errCannotDeserializeRequest.Error())
		return
	}

	err = a.usecase.Logout(reqDto.Token)

	if err != nil {
		switch err {
		case domain.ErrInvalidRefreshToken:
			writeJSONError(res, http.StatusUnauthorized, err.Error())
			return
		case domain.ErrCannotRevokeToken:
			writeJSONError(res, http.StatusInternalServerError, err.Error())
			return
		default:
			writeJSONError(res, http.StatusInternalServerError, err.Error())
			return
		}
	}

	res.WriteHeader(http.StatusNoContent)
}
