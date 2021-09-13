package authorization

import (
	"github.com/golang-jwt/jwt"
)

type Users struct {
	Id         int64      `pg:"id"`
	Email        string    `pg:"email"`
	Password    string    `pg:"password"`
}
type jwtRefreshClaims struct {
	Id int64
	jwt.StandardClaims
}

type jwtAccessClaims struct {
	Id int64
	Email string
	jwt.StandardClaims
}

var jwtKey = []byte("testKey")

