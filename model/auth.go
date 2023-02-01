package model

type Auth struct {
	Id       int
	Email    string
	Password string
}

var AuthData = []Auth{}
