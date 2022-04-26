package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/gorilla/mux"
)

func getMyData(w http.ResponseWriter, r *http.Request, u User, us UserService) {
	w.Write([]byte(u.Email))
	w.Write([]byte("\n"))
	w.Write([]byte(u.FavoriteCake))
}

func wrapJwt(jwt *JWTService, f func(http.ResponseWriter, *http.Request, *JWTService)) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		f(rw, r, jwt)
	}
}

func main() {
	os.Setenv("CAKE_ADMIN_EMAIL", "admin@gmail.com")
	os.Setenv("CAKE_ADMIN_PASSWORD", "pass")
	os.Setenv("CAKE_ADMIN_CAKE", "cake")
	r := mux.NewRouter()
	users := NewInMemoryUserStorage()
	userService := UserService{repository: users}
	Superadmin := User{os.Getenv("CAKE_ADMIN_EMAIL"), os.Getenv("CAKE_ADMIN_PASSWORD"),
		os.Getenv("CAKE_ADMIN_CAKE"), "superadmin", false, BanHistory{}}
	users.Add(Superadmin.Email, Superadmin)
	jwtService, err := NewJWTService("pubkey.rsa", "privkey.rsa")
	if err != nil {
		panic(err)
	}

	go sender(userService.sender)

	r.HandleFunc("/user/me", logRequest(jwtService.jwtAuth(userService, getMyData))).Methods(http.MethodGet)
	r.HandleFunc("/user/favorite_cake", logRequest(jwtService.jwtAuth(userService, changeCakeHandler))).Methods(http.MethodPut)
	r.HandleFunc("/user/email", logRequest(jwtService.jwtAuth(userService, changeEmailHandler))).Methods(http.MethodPut)
	r.HandleFunc("/user/password", logRequest(jwtService.jwtAuth(userService, changePassHandler))).Methods(http.MethodPut)
	r.HandleFunc("/user/register", logRequest(userService.Register)).Methods(http.MethodPost)
	r.HandleFunc("/user/jwt", logRequest(wrapJwt(jwtService, userService.JWT))).Methods(http.MethodPost)

	r.HandleFunc("/admin/ban", logRequest(jwtService.jwtAuthAdmin(userService, banHandler))).Methods(http.MethodPost)
	r.HandleFunc("/admin/unban", logRequest(jwtService.jwtAuthAdmin(userService, unbanHandler))).Methods(http.MethodPost)
	r.HandleFunc("/admin/inspect", logRequest(jwtService.jwtAuthAdmin(userService, inspectHandler))).Methods(http.MethodGet)

	r.HandleFunc("/admin/fire", logRequest(jwtService.jwtAuthSuperadmin(userService, fireHandler))).Methods(http.MethodPost)
	r.HandleFunc("/admin/promote", logRequest(jwtService.jwtAuthSuperadmin(userService, promoteHandler))).Methods(http.MethodPost)

	srv := http.Server{
		Addr:    ":8080",
		Handler: r,
	}

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	go func() {
		<-interrupt
		ctx, cancel := context.WithTimeout(context.Background(),
			5*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}()

	log.Println("Server started, hit Ctrl+C to stop")
	err = srv.ListenAndServe()
	if err != nil {
		log.Println("Server exited with error:", srv.ListenAndServe())
	}
	log.Println("Good bye :)")
}
