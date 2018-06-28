package auth

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
)

func (j *JWT) PrivateKeyPEM() []byte {
	return j.privateKeyPEM
}

func (j *JWT) PublicKeyPEM() []byte {
	return j.publicKeyPEM
}

func (j *JWT) PrivateKey() rsa.PrivateKey {
	return *j.privateKey
}

func (j *JWT) PublicKey() rsa.PublicKey {
	return *j.publicKey
}

func (j *JWT) LoadPrivateKey(fn string) error {
	b, err := ioutil.ReadFile(fn)
	if err != nil {
		return errors.Wrapf(err, "read file: %s", fn)
	}
	j.privateKeyPEM = b

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
	j.publicKeyPEM = b

	k, err := jwt.ParseRSAPublicKeyFromPEM(b)
	if err != nil {
		return errors.Wrap(err, "parse rsa public key")
	}
	j.publicKey = k

	return nil
}

func (j *JWT) DownloadPublicKey(url string, tmout time.Duration, cfg *tls.Config) error {
	// New request.
	req, err := http.NewRequest("GET", url, nil)
	req.Close = true

	// Configure transport.
	tr := &http.Transport{
		TLSClientConfig:    cfg,
		DisableCompression: true,
	}

	// Get a http client.
	clnt := &http.Client{
		Timeout:   tmout,
		Transport: tr,
	}

	// Download public key.
	resp, err := clnt.Do(req)
	if err != nil {
		return errors.Wrapf(err, "download rsa public key: %s", url)
	}
	defer resp.Body.Close()

	// Copy public key.
	b := new(bytes.Buffer)
	if _, err := io.CopyN(b, resp.Body, resp.ContentLength); err != nil {
		return errors.Wrap(err, "copy rsa public key")
	}

	// Parse key.
	k, err := jwt.ParseRSAPublicKeyFromPEM(b.Bytes())
	if err != nil {
		return errors.Wrap(err, "parse rsa public key")
	}
	j.publicKey = k

	return nil
}
