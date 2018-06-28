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
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
)

type Sign *jwt.SigningMethodRSA
type PolicyFn func(c *Claims)
type PermFn func(c *Claims) error

var (
	SignRS256 = jwt.SigningMethodRS256
	SignRS384 = jwt.SigningMethodRS384
	SignRS512 = jwt.SigningMethodRS512
)

type JWT struct {
	sign          Sign
	privateKeyPEM []byte
	publicKeyPEM  []byte
	privateKey    *rsa.PrivateKey
	publicKey     *rsa.PublicKey
	expiration    time.Duration
	skew          time.Duration
}

type Token struct {
	*JWT
	*jwt.Token
}

type Claims struct {
	*jwt.StandardClaims
	*User
}

func NewJWT(sign Sign, expiration time.Duration, skew time.Duration) *JWT {
	return &JWT{
		sign:       sign,
		expiration: expiration,
		skew:       skew,
	}
}

func (j *JWT) NewToken(user *User, policies ...PolicyFn) *Token {
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

	for _, policy := range policies {
		policy(t.Claims.(*Claims))
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
	c := t.Claims.(*Claims)
	c.IssuedAt = time.Now().Add(-t.skew).Unix()
	c.ExpiresAt = time.Now().Add(t.expiration).Unix()
	c.Renewed++
	return t
}

func (t *Token) Sign() (string, error) {
	return t.SignedString(t.privateKey)
}

func (j *JWT) Authorized(handler http.Handler, perms ...PermFn) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		t, err := j.ParseTokenHeader(r)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(err.Error()))
			return
		}

		for _, perm := range perms {
			if err := perm(t.Claims.(*Claims)); err != nil {
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

func (j *JWT) GrpcParseTokenContext(ctx context.Context) (*Token, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, grpc.Errorf(codes.Unauthenticated, "no authorization header")
	}

	t, ok := md["authorization"]
	if !ok {
		return nil, grpc.Errorf(codes.Unauthenticated, "no authorization header")
	}

	return j.ParseToken(t[0])
}

func (j *JWT) GrpcAuthorized(ctx context.Context, perms ...PermFn) (*User, error) {
	t, err := j.GrpcParseTokenContext(ctx)
	if err != nil {
		return nil, err
	}

	for _, perm := range perms {
		if err := perm(t.Claims.(*Claims)); err != nil {
			return nil, err
		}
	}

	return t.Claims.(*Claims).User, nil
}
