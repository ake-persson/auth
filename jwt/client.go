package jwt

import (
	"crypto/rsa"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
)

type JWTClient struct {
	publicKeyPEM []byte
	publicKey    *rsa.PublicKey
}

func (j *JWTClient) ParseToken(token string) (*Token, error) {
	t, err := jwt.ParseWithClaims(token, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return j.publicKey, nil
	})
	if err != nil {
		return nil, err
	}
	return &Token{t}, nil
}

func (j *JWTClient) ParseTokenReader(reader io.ReadCloser) (*Token, error) {
	b, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	return j.ParseToken(string(b))
}

func (j *JWTClient) ParseTokenHeader(r *http.Request) (*Token, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return nil, errors.New("no authorization header")
	}
	return j.ParseToken(strings.Split(h, " ")[1])
}

func (j *JWTClient) ParseTokenContext(ctx context.Context) (*Token, error) {
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
