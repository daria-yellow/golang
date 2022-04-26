// Copyright 2013 The Gorilla WebSocket Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	//"cake/jwt"
	"flag"
	"log"
	"net/http"
)

var addr = flag.String("addr", ":8080", "http service address")

func serveHome(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL)
	if r.URL.Path != "/" {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	http.ServeFile(w, r, "home.html")
}

func main() {
	flag.Parse()
	hub := newHub()
	go hub.run()
	go hub.reciever()

	// jwtService, err := NewJWTService("pubkey.rsa", "privkey.rsa")
	// if err != nil {
	// 	panic(err)
	// }

	http.HandleFunc("/", serveHome)
	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		// authHeader := r.Header.Get("Authorization")
		// token := strings.TrimPrefix(authHeader, "Bearer ")
		// auth, err := jwtService.ParseJWT(token)
		// if err != nil {
		// 	w.WriteHeader(401)
		// 	w.Write([]byte("unauthorized"))
		// 	return
		// }
		serveWs(hub, w, r)
	})
	err := http.ListenAndServe(*addr, nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
