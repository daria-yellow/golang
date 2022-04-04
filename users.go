package main

import (
	"crypto/md5"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"unicode"
)

type User struct {
	Email          string
	PasswordDigest string
	FavoriteCake   string
	Role           string
	Banned         bool
	BanHistory     BanHistory
}

type UserRepository interface {
	Add(string, User) error
	Get(string) (User, error)
	Update(string, User) error
	Delete(string) (User, error)
}

type UserService struct {
	repository UserRepository
}

type UserRegisterParams struct {
	Email        string `json:"email"`
	Password     string `json:"password"`
	FavoriteCake string `json:"favorite_cake"`
}

type ChangeCakeParams struct {
	Email        string `json:"email"`
	FavoriteCake string `json:"favorite_cake"`
}

type ChangePassParams struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type ChangeEmailParams struct {
	Email     string `json:"email"`
	New_email string `json:"new email"`
}

var emailRegex = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

func validateRegisterParams(p *UserRegisterParams) error {
	if !emailRegex.MatchString(p.Email) {
		return errors.New("Invalid email")
	}

	if len(p.Email) < 3 {
		return errors.New("Invalid email")
	}

	if len(p.Password) < 8 {
		return errors.New("Password should consist at least 8 characters")
	}

	if p.FavoriteCake == "" {
		return errors.New("Enter your cake")
	}

	for _, i := range p.FavoriteCake {
		if !unicode.IsLetter(i) {
			return errors.New("Invalid cake: should consist only letters!")
		}
	}
	return nil
}

func validateEmailParams(p *ChangeEmailParams) error {
	if !emailRegex.MatchString(p.New_email) {
		return errors.New("Invalid email")
	}
	if len(p.New_email) < 3 {
		return errors.New("Invalid email")
	}
	return nil
}

func validatePassParams(p *ChangePassParams) error {
	if len(p.Password) < 8 {
		return errors.New("Invalid password")
	}
	return nil
}

func validateCakeParams(p *ChangeCakeParams) error {
	if p.FavoriteCake == "" {
		return errors.New("Invalid cake")
	}

	for _, i := range p.FavoriteCake {
		if !unicode.IsLetter(i) {
			return errors.New("Invalid cake: should consist only letters!")
		}
	}
	return nil
}

func (u *UserService) Register(w http.ResponseWriter, r *http.Request) {
	params := &UserRegisterParams{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil {
		handleError(errors.New("could not read params"), w)
		return
	}

	if err := validateRegisterParams(params); err != nil {
		handleError(err, w)
		return
	}

	passwordDigest := md5.New().Sum([]byte(params.Password))
	newUser := User{
		Email:          params.Email,
		PasswordDigest: string(passwordDigest),
		FavoriteCake:   params.FavoriteCake,
	}
	err = u.repository.Add(params.Email, newUser)

	if err != nil {
		handleError(err, w)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("registered"))
}

func changeCakeHandler(w http.ResponseWriter, r *http.Request, u User, us UserRepository) {
	params := &ChangeCakeParams{}
	err := json.NewDecoder(r.Body).Decode(params)

	if err != nil {
		handleError(errors.New("could not read params"), w)
		return
	}

	if err := validateCakeParams(params); err != nil {
		handleError(err, w)
		return
	}

	if params.Email != u.Email {
		w.WriteHeader(401)
		w.Write([]byte("Your are not logged in"))
		return
	}

	if u.Banned == true {
		w.WriteHeader(401)
		w.Write([]byte("Your are banned because : "))
		w.Write([]byte(u.BanHistory.Why))
		return
	}

	newCake := User{
		Email:          u.Email,
		FavoriteCake:   params.FavoriteCake,
		PasswordDigest: u.PasswordDigest,
	}
	err = us.Update(u.Email, newCake)

	if err != nil {
		handleError(err, w)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("Your favorite cake have been changed"))
}

func changePassHandler(w http.ResponseWriter, r *http.Request, u User, us UserRepository) {
	params := &ChangePassParams{}
	err := json.NewDecoder(r.Body).Decode(params)

	if err != nil {
		handleError(errors.New("could not read params"), w)
		return
	}

	if err := validatePassParams(params); err != nil {
		handleError(err, w)
		return
	}

	if params.Email != u.Email {
		w.WriteHeader(401)
		w.Write([]byte("Your are not logged in"))
		return
	}

	if u.Banned == true {
		w.WriteHeader(401)
		w.Write([]byte("Your are banned because : "))
		w.Write([]byte(u.BanHistory.Why))
		return
	}

	passwordDigest := md5.New().Sum([]byte(params.Password))
	newPass := User{
		Email:          u.Email,
		FavoriteCake:   u.FavoriteCake,
		PasswordDigest: string(passwordDigest),
	}
	err = us.Update(u.Email, newPass)

	if err != nil {
		handleError(err, w)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("Your password have been changed"))
}

func changeEmailHandler(w http.ResponseWriter, r *http.Request, u User, us UserRepository) {
	params := &ChangeEmailParams{}
	err := json.NewDecoder(r.Body).Decode(params)

	if err != nil {
		handleError(errors.New("could not read params"), w)
		return
	}

	if err := validateEmailParams(params); err != nil {
		handleError(err, w)
		return
	}

	if params.Email != u.Email {
		w.WriteHeader(401)
		w.Write([]byte("Your are not logged in"))
		return
	}

	if u.Banned == true {
		w.WriteHeader(401)
		w.Write([]byte("Your are banned because : "))
		w.Write([]byte(u.BanHistory.Why))
		return
	}

	newEmail := User{
		Email:          params.New_email,
		FavoriteCake:   u.FavoriteCake,
		PasswordDigest: u.PasswordDigest,
	}
	us.Delete(u.Email)
	err = us.Add(params.New_email, newEmail)

	if err != nil {
		handleError(err, w)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("Your email have been changed"))
}

func handleError(err error, w http.ResponseWriter) {
	w.WriteHeader(http.StatusUnprocessableEntity)
	w.Write([]byte(err.Error()))
}
