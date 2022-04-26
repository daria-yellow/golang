package main

import (
	"crypto/md5"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/openware/rango/pkg/auth"
)

type JWTService struct {
	keys *auth.KeyStore
}

func NewJWTService(privKeyPath, pubKeyPath string) (*JWTService, error) {
	keys, err := auth.LoadOrGenerateKeys(privKeyPath, pubKeyPath)
	if err != nil {
		return nil, err
	}
	return &JWTService{keys: keys}, nil
}
func (j *JWTService) GenearateJWT(u User) (string, error) {
	return auth.ForgeToken("empty", u.Email, "empty", 0, j.keys.
		PrivateKey, nil)
}
func (j *JWTService) ParseJWT(jwt string) (auth.Auth, error) {
	return auth.ParseAndValidate(jwt, j.keys.PublicKey)
}

type JWTParams struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (u *UserService) JWT(w http.ResponseWriter, r *http.Request, jwtService *JWTService) {
	params := &JWTParams{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil {
		handleError(errors.New("could not read params"), w)
		return
	}
	passwordDigest := md5.New().Sum([]byte(params.Password))
	user, err := u.repository.Get(params.Email)
	if err != nil {
		handleError(err, w)
		return
	}

	if string(passwordDigest) != user.PasswordDigest && user.Email != os.Getenv("CAKE_ADMIN_EMAIL") {
		handleError(errors.New("invalid login params"), w)
		return
	}

	if user.Banned == true {
		w.WriteHeader(401)
		u.sender <- []byte("Your are banned because : ")
		for key, _ := range user.BanHistory.history {
			if user.BanHistory.history[key].WhoUnbanned == "" {
				w.Write([]byte(user.BanHistory.history[key].Why))
			}
		}
		return
	}

	token, err := jwtService.GenearateJWT(user)
	if err != nil {
		handleError(err, w)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(token))
}

type ProtectedHandler func(rw http.ResponseWriter, r *http.Request, u User, us UserService)

func (j *JWTService) jwtAuth(
	users UserService,
	h ProtectedHandler,
) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		token := strings.TrimPrefix(authHeader, "Bearer ")
		auth, err := j.ParseJWT(token)
		if err != nil {
			rw.WriteHeader(401)
			users.sender <- []byte("unauthorized")
			return
		}
		user, err := users.repository.Get(auth.Email)
		if err != nil {
			rw.WriteHeader(401)
			users.sender <- []byte("unauthorized")
			return
		}
		h(rw, r, user, users)
	}
}

func (j *JWTService) jwtAuthAdmin(
	users UserService,
	h ProtectedHandler,
) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		token := strings.TrimPrefix(authHeader, "Bearer ")
		auth, err := j.ParseJWT(token)
		if err != nil {
			rw.WriteHeader(401)
			users.sender <- []byte("unauthorized")
			return
		}
		user, err := users.repository.Get(auth.Email)
		if err != nil {
			rw.WriteHeader(401)
			users.sender <- []byte("unauthorized")
			return
		}
		if user.Role != "superadmin" && user.Role != "admin" {
			rw.WriteHeader(401)
			users.sender <- []byte("You should be admin to access this page")
			return
		}
		h(rw, r, user, users)
	}
}

func (j *JWTService) jwtAuthSuperadmin(
	users UserService,
	h ProtectedHandler,
) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		token := strings.TrimPrefix(authHeader, "Bearer ")
		auth, err := j.ParseJWT(token)
		if err != nil {
			rw.WriteHeader(401)
			users.sender <- []byte("unauthorized")
			return
		}
		user, err := users.repository.Get(auth.Email)
		if err != nil {
			rw.WriteHeader(401)
			users.sender <- []byte("unauthorized")
			return
		}
		if user.Role != "superadmin" {
			rw.WriteHeader(401)
			users.sender <- []byte("You should be a superadmin to access this page")
			return
		}
		h(rw, r, user, users)
	}
}
