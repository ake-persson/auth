package auth

import (
	"crypto/rsa"
	"io/ioutil"

	"github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
)

func LoadPrivKey(fn string) (*rsa.PrivateKey, error) {
	b, err := ioutil.ReadFile(fn)
	if err != nil {
		return nil, errors.Wrapf(err, "read file: %s", fn)
	}

	k, err := jwt.ParseRSAPrivateKeyFromPEM(b)
	if err != nil {
		return nil, errors.Wrap(err, "parse rsa private key")
	}

	return k, nil
}

func LoadPubKey(fn string) (*rsa.PublicKey, error) {
	b, err := ioutil.ReadFile(fn)
	if err != nil {
		return nil, errors.Wrapf(err, "read file: %s", fn)
	}

	k, err := jwt.ParseRSAPublicKeyFromPEM(b)
	if err != nil {
		return nil, errors.Wrap(err, "parse rsa public key")
	}

	return k, nil
}
