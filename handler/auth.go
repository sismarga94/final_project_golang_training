package handler

import (
	"encoding/json"
	"finalproject/model"
	"finalproject/utils"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"text/template"

	"github.com/gorilla/sessions"
	"github.com/labstack/echo"
)

type AuthHandler struct {
	store *sessions.CookieStore
}

func NewAuthHandler(store *sessions.CookieStore) *AuthHandler {
	return &AuthHandler{
		store: store,
	}
}

type M map[string]interface{}

const (
	CSRF_TokenHeader = "X-CSRF-TOKEN"
	CSRF_Key         = "csrf"
	SESSION_ID       = "SESSIONID"
	secret           = "hacktiv8hacktiv8hacktiv8hacktiv8"
)

var tmpl = template.Must(template.ParseGlob("./static/*.html"))

func (a *AuthHandler) FormRegister(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("./static/register.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (a *AuthHandler) FormLogin(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("./static/login.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (a *AuthHandler) FormChat(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("./static/chat.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sess, _ := a.store.Get(r, SESSION_ID)

	email := sess.Values["data"].(string)
	email = strings.Split(email, "@")[0]
	err = tmpl.Execute(w, map[string]string{"email": email})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}

func (a *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	req := new(model.Auth)
	bytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Printf("err = %v", err.Error())
		return
	}
	json.Unmarshal(bytes, &req)

	var data = &model.Auth{}
	data = nil
	for _, auth := range model.AuthData {
		if auth.Email == req.Email && utils.Decrypt(auth.Password, secret) == req.Password {
			data = &auth
			break
		}
	}

	if data == nil {
		http.Error(w, "not found", http.StatusInternalServerError)
		return
	}

	payload := M{
		"payload": data,
		"status":  http.StatusOK,
	}

	sess, _ := a.store.Get(r, SESSION_ID)

	sess.Values["is_login"] = true
	sess.Values["data"] = data.Email

	err = sess.Save(r, w)
	if err != nil {
		http.Error(w, "error save session", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	jsonResp, err := json.Marshal(payload)
	if err != nil {
		log.Fatalf("Error happened in JSON marshal. Err: %s", err)
	}
	w.Write(jsonResp)
	return
}

func (a *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	req := new(model.Auth)
	bytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Printf("err = %v", err.Error())
		return
	}
	json.Unmarshal(bytes, &req)

	if req.Email == "" || req.Password == "" {
		http.Error(w, "register failed", http.StatusBadRequest)
		return
	}
	req.Password = utils.Encrypt(req.Password, secret)
	fmt.Printf("password = %v\n", req.Password)
	req.Id = len(model.AuthData) + 1

	model.AuthData = append(model.AuthData, *req)
	payload := M{
		"message": "register success",
		"status":  http.StatusCreated,
	}
	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "application/json")
	jsonResp, err := json.Marshal(payload)
	if err != nil {
		log.Fatalf("Error happened in JSON marshal. Err: %s", err)
	}
	w.Write(jsonResp)
	return
}

func (a *AuthHandler) GetCSRF(ctx echo.Context) error {
	data := make(M)
	data[CSRF_Key] = ctx.Get(CSRF_Key)

	return ctx.JSON(http.StatusOK, data)
}
