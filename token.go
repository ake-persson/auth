package auth

import (
	"crypto/rsa"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type ClaimsFn func(c *Claims)

type Token struct {
	*jwt.Token
}

type Claims struct {
	*jwt.StandardClaims
	*User
}

func NewToken(user *User, expiration time.Duration, skew time.Duration, fns ...ClaimsFn) *Token {
	t := &Token{jwt.New(jwt.SigningMethodRS512)}

	t.Claims = &Claims{
		StandardClaims: &jwt.StandardClaims{
			IssuedAt:  time.Now().Add(-skew).Unix(),
			ExpiresAt: time.Now().Add(expiration).Unix(),
		},
		User: user,
	}

	for _, fn := range fns {
		fn(t.Claims.(*Claims))
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

func ParseTokenHeader(r *http.Request, key *rsa.PublicKey) (*Token, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return nil, errors.New("no authorization header")
	}

	return ParseToken(strings.Split(h, " ")[1], key)
}

func (t *Token) Authorized() error {
	return nil
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
