package main

import (
	"finalproject/client"
	"finalproject/handler"
	"net/http"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

const (
	CSRF_TokenHeader = "X-CSRF-TOKEN"
	CSRF_Key         = "csrf"
)

type M map[string]interface{}

func main() {
	// initialize Hub struct
	hub := client.NewHub()
	go hub.Run()

	key := securecookie.GenerateRandomKey(32)
	store := sessions.NewCookieStore(key)

	handler := handler.NewAuthHandler(store)
	http.HandleFunc("/", handler.FormLogin)
	http.HandleFunc("/form/login", handler.FormLogin)
	http.HandleFunc("/form/register", handler.FormRegister)
	http.HandleFunc("/form/chat", handler.FormChat)
	http.HandleFunc("/auth/register", handler.Register)
	http.HandleFunc("/auth/login", handler.Login)

	// each new connection will hit ServeWs
	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		client.ServeWs(hub, w, r)
	})
	http.ListenAndServe(":4444", nil)
}
