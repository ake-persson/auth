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

type SignRSA *jwt.SigningMethodRSA

var (
	SignRSA256 = jwt.SigningMethodRS256
	SignRSA384 = jwt.SigningMethodRS384
	SignRSA512 = jwt.SigningMethodRS512
)

type JWT struct {
	sign       SignRSA
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	expiration time.Duration
	skew       time.Duration
}

type Token struct {
	*JWT
	*jwt.Token
}

type Claims struct {
	*jwt.StandardClaims
	*User
}

func NewJWT(sign SignRSA, expiration time.Duration, skew time.Duration) *JWT {
	return &JWT{
		sign:       sign,
		expiration: expiration,
		skew:       skew,
	}
}

func (j *JWT) NewToken(user *User, fns ...func(c *Claims)) *Token {
	t := &Token{
		JWT:   j,
		Token: jwt.New(jwt.SigningMethodRS512),
	}

	t.Claims = &Claims{
		StandardClaims: &jwt.StandardClaims{
			IssuedAt:  time.Now().Add(-j.skew).Unix(),
			ExpiresAt: time.Now().Add(j.expiration).Unix(),
		},
		User: user,
	}

	for _, fn := range fns {
		fn(t.Claims.(*Claims))
	}

	return t
}

func (j *JWT) ParseToken(token string) (*Token, error) {
	t, err := jwt.ParseWithClaims(token, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return j.publicKey, nil
	})
	if err != nil {
		return nil, err
	}

	return &Token{
		JWT:   j,
		Token: t,
	}, nil
}

func (j *JWT) ParseTokenReader(reader io.ReadCloser) (*Token, error) {
	b, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	return j.ParseToken(string(b))
}

func (j *JWT) ParseTokenHeader(r *http.Request) (*Token, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return nil, errors.New("no authorization header")
	}
	return j.ParseToken(strings.Split(h, " ")[1])
}

func (t *Token) Renew() *Token {
	claims := t.Claims.(jwt.MapClaims)
	claims["iat"] = time.Now().Add(-t.skew).Unix()
	claims["exp"] = time.Now().Add(t.expiration).Unix()
	return t
}

func (t *Token) Sign() (string, error) {
	return t.SignedString(t.privateKey)
}

func (j *JWT) Authorized(handler http.Handler, fns ...func(c *Claims) error) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		t, err := j.ParseTokenHeader(r)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(err.Error()))
			return
		}

		for _, fn := range fns {
			if err := fn(t.Claims.(*Claims)); err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Write([]byte(err.Error()))
				return
			}
		}

		handler.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}
