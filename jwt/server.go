package auth

import (
	"crypto/rsa"
	"time"

	"github.com/dgrijalva/jwt-go"
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

func NewJWTServer(signingAlgo SigningAlgo, expiration time.Duration, skew time.Duration) *JWTServer {
	return &JWTServer{
		signingAlgo: signingAlgo,
		expiration:  expiration,
		skew:        skew,
	}
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

func (j *JWTServer) SignToken(t *Token) (string, error) {
	return t.SignedString(j.privateKey)
}

func (j *JWTServer) RenewToken(t *Token) {
	c := t.Claims.(*Claims)
	c.IssuedAt = time.Now().Add(-j.skew).Unix()
	c.ExpiresAt = time.Now().Add(j.expiration).Unix()
	c.Renewed++
}
