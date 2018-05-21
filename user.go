package auth

import (
	"crypto/rsa"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type User struct {
	DN       string `json:"dn,omitempty"`
	UID      int    `json:"uid,omitempty"`
	Username string `json:"username"`
	Name     string `json:"name"`
	Mail     string `json:"mail"`
	Groups   Groups `json:"-"`
}

type Group struct {
	DN   string `json:"dn,omitempty"`
	GID  int    `json:"gid,omitempty"`
	Name string `json:"name"`
}

type Groups []*Group

type Claims struct {
	*jwt.StandardClaims
	*User
}

func (u *User) Token(k *rsa.PrivateKey, exp time.Duration) (string, error) {
	t := jwt.New(jwt.SigningMethodRS512)

	t.Claims = &Claims{
		StandardClaims: &jwt.StandardClaims{
			IssuedAt:  time.Now().Unix() - 5*60*60, // Allow for 5 min. missmatch
			ExpiresAt: time.Now().Add(time.Duration(exp) * time.Second).Unix(),
		},
		User: u,
	}

	return t.SignedString(k)
}
