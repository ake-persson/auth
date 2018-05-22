package auth

import (
	"io/ioutil"

	"github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
)

func (j *JWT) LoadPrivateKey(fn string) error {
	b, err := ioutil.ReadFile(fn)
	if err != nil {
		return errors.Wrapf(err, "read file: %s", fn)
	}

	k, err := jwt.ParseRSAPrivateKeyFromPEM(b)
	if err != nil {
		return errors.Wrap(err, "parse rsa private key")
	}
	j.privateKey = k

	return nil
}

func (j *JWT) LoadPublicKey(fn string) error {
	b, err := ioutil.ReadFile(fn)
	if err != nil {
		return errors.Wrapf(err, "read file: %s", fn)
	}

	k, err := jwt.ParseRSAPublicKeyFromPEM(b)
	if err != nil {
		return errors.Wrap(err, "parse rsa public key")
	}
	j.publicKey = k

	return nil
}
