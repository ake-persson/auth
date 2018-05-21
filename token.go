package auth

import (
	"crypto/rsa"
	"io"
	"io/ioutil"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type Token struct {
	*jwt.Token
}

type Claims struct {
	*jwt.StandardClaims
	*User
}

func NewToken(user *User, expiration time.Duration, skew time.Duration) *Token {
	t := &Token{jwt.New(jwt.SigningMethodRS512)}

	t.Claims = &Claims{
		StandardClaims: &jwt.StandardClaims{
			IssuedAt:  time.Now().Add(-skew).Unix(),
			ExpiresAt: time.Now().Add(expiration).Unix(),
		},
		User: user,
	}

	return t
}

func ParseToken(token string, key *rsa.PublicKey) (*Token, error) {
	t, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return key, nil
	})
	if err != nil {
		return nil, err
	}

	return &Token{t}, nil
}

func ParseTokenReader(reader io.ReadCloser, key *rsa.PublicKey) (*Token, error) {
	b, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	return ParseToken(string(b), key)
}

func (t *Token) Renew(expiration time.Duration, skew time.Duration) *Token {
	claims := t.Claims.(jwt.MapClaims)
	claims["iat"] = time.Now().Add(-skew).Unix()
	claims["exp"] = time.Now().Add(expiration).Unix()

	return t
}

func (t *Token) Sign(key *rsa.PrivateKey) (string, error) {
	return t.SignedString(key)
}
