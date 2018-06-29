package jwt

import (
	"crypto/rsa"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
)

type JWTClient struct {
	publicKeyPEM []byte
	publicKey    *rsa.PublicKey
}

type JWTClientOption func(*JWTClient) error

func NewJWTClient(options ...JWTClientOption) (*JWTClient, error) {
	j := &JWTClient{}

	for _, option := range options {
		if err := option(j); err != nil {
			return nil, err
		}
	}

	return j, nil
}

func (j *JWTClient) PublicKeyPEM() []byte {
	return j.publicKeyPEM
}

func (j *JWTClient) PublicKey() *rsa.PublicKey {
	return j.publicKey
}

func (j *JWTClient) setPublicKey(b []byte) error {
	j.publicKeyPEM = b

	k, err := jwt.ParseRSAPublicKeyFromPEM(b)
	if err != nil {
		return errors.Wrap(err, "parse rsa public key")
	}
	j.publicKey = k

	return nil
}

func (j *JWTClient) loadPublicKey(fn string) error {
	b, err := ioutil.ReadFile(fn)
	if err != nil {
		return errors.Wrapf(err, "read file: %s", fn)
	}
	return j.setPublicKey(b)
}

func WithPublicKey(publicKey []byte) JWTClientOption {
	return func(j *JWTClient) error {
		return j.setPublicKey(publicKey)
	}
}

func WithLoadPublicKey(publicKeyFile string) JWTClientOption {
	return func(j *JWTClient) error {
		return j.loadPublicKey(publicKeyFile)
	}
}

func (j *JWTClient) ParseToken(token string) (*Token, error) {
	t, err := jwt.ParseWithClaims(token, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return j.publicKey, nil
	})
	if err != nil {
		return nil, err
	}
	return &Token{Token: t}, nil
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

func (j *JWTClient) Authorized(t *Token, perms ...PermFunc) error {
	for _, perm := range perms {
		if err := perm(t.Claims.(*Claims)); err != nil {
			return err
		}
	}
	return nil
}

func (j *JWTClient) AuthorizedHandler(handler http.Handler, perms ...PermFunc) http.Handler {
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

func (j *JWTClient) AuthorizedGrpc(ctx context.Context, perms ...PermFunc) error {
	t, err := j.ParseTokenContext(ctx)
	if err != nil {
		return err
	}

	for _, perm := range perms {
		if err := perm(t.Claims.(*Claims)); err != nil {
			return grpc.Errorf(codes.Unauthenticated, err.Error())
		}
	}
	return nil
}

func (t *Token) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{
		"authorization": t.SignedToken,
	}, nil
}

func (t *Token) RequireTransportSecurity() bool {
	return true
}
