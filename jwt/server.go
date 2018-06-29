package jwt

import (
	"crypto/rsa"
	"io/ioutil"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"

	"github.com/mickep76/auth"
)

type JWTServer struct {
	signingAlgo   SigningAlgo
	privateKeyPEM []byte
	privateKey    *rsa.PrivateKey
	expiration    time.Duration
	skew          time.Duration
	*JWTClient
}

type JWTServerOption func(*JWTServer) error

func NewJWTServer(signingAlgo SigningAlgo, expiration time.Duration, skew time.Duration, options ...JWTServerOption) (*JWTServer, error) {
	c, err := NewJWTClient()
	if err != nil {
		return nil, err
	}

	j := &JWTServer{
		signingAlgo: signingAlgo,
		expiration:  expiration,
		skew:        skew,
		JWTClient:   c,
	}

	for _, option := range options {
		if err := option(j); err != nil {
			return nil, err
		}
	}

	return j, nil
}

func (j *JWTServer) NewToken(u *auth.User, policies ...PolicyFunc) *Token {
	t := &Token{
		Token: jwt.New((*jwt.SigningMethodRSA)(j.signingAlgo)),
	}

	t.Claims = &Claims{
		StandardClaims: &jwt.StandardClaims{
			IssuedAt:  time.Now().Add(-j.skew).Unix(),
			ExpiresAt: time.Now().Add(j.expiration).Unix(),
		},
		User:    u,
		Renewed: 0,
	}

	for _, policy := range policies {
		policy(t.Claims.(*Claims))
	}

	return t
}

func (j *JWTServer) PrivateKeyPEM() []byte {
	return j.privateKeyPEM
}

func (j *JWTServer) PrivateKey() *rsa.PrivateKey {
	return j.privateKey
}

func (j *JWTServer) setPrivateKey(b []byte) error {
	j.privateKeyPEM = b

	k, err := jwt.ParseRSAPrivateKeyFromPEM(b)
	if err != nil {
		return errors.Wrap(err, "parse rsa private key")
	}
	j.privateKey = k

	return nil
}

func (j *JWTServer) loadPrivateKey(fn string) error {
	b, err := ioutil.ReadFile(fn)
	if err != nil {
		return errors.Wrapf(err, "read file: %s", fn)
	}
	return j.setPrivateKey(b)
}

func WithKeys(privateKey []byte, publicKey []byte) JWTServerOption {
	return func(j *JWTServer) error {
		if err := j.setPublicKey(publicKey); err != nil {
			return err
		}
		return j.setPrivateKey(privateKey)
	}
}

func WithLoadKeys(privateKeyFile string, publicKeyFile string) JWTServerOption {
	return func(j *JWTServer) error {
		if err := j.loadPublicKey(publicKeyFile); err != nil {
			return err
		}
		return j.loadPrivateKey(privateKeyFile)
	}
}

func (j *JWTServer) SignToken(t *Token) (string, error) {
	return t.SignedString(j.privateKey)
}

func (j *JWTServer) RenewToken(t *Token) {
	c := t.Claims.(*Claims)
	c.IssuedAt = time.Now().Add(-j.skew).Unix()
	c.ExpiresAt = time.Now().Add(j.expiration).Unix()
	c.Renewed++
}
