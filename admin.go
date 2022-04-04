package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"
)

type BanHistory struct {
	WhoBanned   string
	WhenBanned  time.Time
	Why         string
	WhoUnbanned string
}

type BanParams struct {
	Email  string `json:"email"`
	Reason string `json:"reason"`
}

type UnBanParams struct {
	Email string `json:"email"`
}

func banHandler(w http.ResponseWriter, r *http.Request, u User, us UserRepository) {
	params := &BanParams{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil {
		handleError(errors.New("could not read params"), w)
		return
	}
	user, err := us.Get(params.Email)
	if err != nil {
		w.WriteHeader(401)
		w.Write([]byte("This user doesn't exist"))
		return
	}
	if (user.Role == "admin" || user.Role == "superadmin") && u.Role != "superadmin" {
		w.WriteHeader(401)
		w.Write([]byte("Only superadmin can ban admin!"))
		return
	}
	Banhistory := BanHistory{u.Email, time.Now(), params.Reason, ""}
	Ban := User{
		Email:          user.Email,
		FavoriteCake:   user.FavoriteCake,
		PasswordDigest: user.PasswordDigest,
		Role:           user.Role,
		Banned:         true,
		BanHistory:     Banhistory,
	}
	err = us.Update(user.Email, Ban)
	if err != nil {
		handleError(err, w)
		return
	}
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("The user have been banned bacause: " + params.Reason))
}

func unbanHandler(w http.ResponseWriter, r *http.Request, u User, us UserRepository) {
	params := &UnBanParams{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil {
		handleError(errors.New("could not read params"), w)
		return
	}
	user, err := us.Get(params.Email)
	if err != nil {
		w.WriteHeader(401)
		w.Write([]byte("This user doesn't exist"))
		return
	}
	if (user.Role == "admin" || user.Role == "superadmin") && u.Role != "superadmin" {
		w.WriteHeader(401)
		w.Write([]byte("Only superadmin can unban admin!"))
		return
	}
	user.BanHistory.WhoUnbanned = u.Email
	UnBan := User{
		Email:          user.Email,
		FavoriteCake:   user.FavoriteCake,
		PasswordDigest: user.PasswordDigest,
		Role:           user.Role,
		Banned:         false,
		BanHistory:     user.BanHistory,
	}
	err = us.Update(user.Email, UnBan)
	if err != nil {
		handleError(err, w)
		return
	}
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("The user have been unbanned"))
}

func inspectHandler(w http.ResponseWriter, r *http.Request, u User, us UserRepository) {
	params := &UnBanParams{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil {
		handleError(errors.New("could not read params"), w)
		return
	}
	user, err := us.Get(params.Email)
	if err != nil {
		w.WriteHeader(401)
		w.Write([]byte("This user doesn't exist"))
		return
	}
	if (user.Role == "admin" || user.Role == "superadmin") && u.Role != "superadmin" {
		w.WriteHeader(401)
		w.Write([]byte("Only superadmin can inspect admin!"))
		return
	}

	/*email := r.URL.Query().Get("email")
	w.Write([]byte(("email :" + email)))*/
	w.Write([]byte("User : " + user.Email + "\n"))
	w.Write([]byte("Favorite cake : " + user.FavoriteCake + "\n"))
	w.Write([]byte("Banned : " + strconv.FormatBool(user.Banned) + "\n"))
	w.Write([]byte("Role : " + user.Role + "\n"))
	w.Write([]byte("Who banned : " + user.BanHistory.WhoBanned + "\n"))
	w.Write([]byte("When : " + user.BanHistory.WhenBanned.String() + "\n"))
	w.Write([]byte("Why : " + user.BanHistory.Why + "\n"))
	w.Write([]byte("Who unbanned : " + user.BanHistory.WhoUnbanned + "\n"))
}

func promoteHandler(w http.ResponseWriter, r *http.Request, u User, us UserRepository) {
	params := &UnBanParams{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil {
		handleError(errors.New("could not read params"), w)
		return
	}
	if u.Role != "superadmin" {
		w.WriteHeader(401)
		w.Write([]byte("Only superadmin can promote!"))
		return
	}
	user, err := us.Get(params.Email)
	if err != nil {
		w.WriteHeader(401)
		w.Write([]byte("This user doesn't exist"))
		return
	}
	promote := User{
		Email:          user.Email,
		FavoriteCake:   user.FavoriteCake,
		PasswordDigest: user.PasswordDigest,
		Role:           "admin",
		Banned:         user.Banned,
		BanHistory:     user.BanHistory,
	}
	err = us.Update(user.Email, promote)
	if err != nil {
		handleError(err, w)
		return
	}
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("The user have been promoted"))
}

func fireHandler(w http.ResponseWriter, r *http.Request, u User, us UserRepository) {
	params := &UnBanParams{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil {
		handleError(errors.New("could not read params"), w)
		return
	}
	user, err := us.Get(params.Email)
	if err != nil {
		w.WriteHeader(401)
		w.Write([]byte("This user doesn't exist"))
		return
	}
	if u.Role != "superadmin" {
		w.WriteHeader(401)
		w.Write([]byte("Only superadmin can fire!"))
		return
	}
	fire := User{
		Email:          user.Email,
		FavoriteCake:   user.FavoriteCake,
		PasswordDigest: user.PasswordDigest,
		Role:           "",
		Banned:         user.Banned,
		BanHistory:     user.BanHistory,
	}
	err = us.Update(user.Email, fire)
	if err != nil {
		handleError(err, w)
		return
	}
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("The user have been fired"))
}
