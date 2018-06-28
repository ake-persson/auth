package jwt

import (
	"crypto/rsa"
	"io/ioutil"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
)

type JWTServer struct {
	signingAlgo   SigningAlgo
	privateKeyPEM []byte
	publicKeyPEM  []byte
	privateKey    *rsa.PrivateKey
	publicKey     *rsa.PublicKey
	expiration    time.Duration
	skew          time.Duration
}

type JWTServerOption func(*JWTServer) error

func NewJWTServer(signingAlgo SigningAlgo, expiration time.Duration, skew time.Duration, options ...JWTServerOption) (*JWTServer, error) {
	return &JWTServer{
		signingAlgo: signingAlgo,
		expiration:  expiration,
		skew:        skew,
	}, nil
}

func (j *JWTServer) NewToken(c *Claims, policies ...PolicyFunc) *Token {
	t := &Token{
		Token: jwt.New((*jwt.SigningMethodRSA)(j.signingAlgo)),
	}

	c.StandardClaims = &jwt.StandardClaims{
		IssuedAt:  time.Now().Add(-j.skew).Unix(),
		ExpiresAt: time.Now().Add(j.expiration).Unix(),
	}
	c.Renewed = 0

	for _, policy := range policies {
		policy(t.Claims.(*Claims))
	}

	return t
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

func (j *JWTServer) setPublicKey(b []byte) error {
	j.publicKeyPEM = b

	k, err := jwt.ParseRSAPublicKeyFromPEM(b)
	if err != nil {
		return errors.Wrap(err, "parse rsa public key")
	}
	j.publicKey = k

	return nil
}

func (j *JWTServer) loadPrivateKey(fn string) error {
	b, err := ioutil.ReadFile(fn)
	if err != nil {
		return errors.Wrapf(err, "read file: %s", fn)
	}
	return j.setPrivateKey(b)
}

func (j *JWTServer) loadPublicKey(fn string) error {
	b, err := ioutil.ReadFile(fn)
	if err != nil {
		return errors.Wrapf(err, "read file: %s", fn)
	}
	return j.setPublicKey(b)
}

func WithRSAKeys(privateKey []byte, publicKey []byte) JWTServerOption {
	return func(j *JWTServer) error {
		if err := j.setPrivateKey(privateKey); err != nil {
			return err
		}
		return j.setPublicKey(publicKey)
	}
}

func WithLoadRSAKeys(privateKeyFile string, publicKeyFile string) JWTServerOption {
	return func(j *JWTServer) error {
		if err := j.loadPrivateKey(privateKeyFile); err != nil {
			return err
		}
		return j.loadPublicKey(publicKeyFile)
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
