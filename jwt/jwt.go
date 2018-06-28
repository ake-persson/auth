package jwt

import (
	"github.com/dgrijalva/jwt-go"
)

type SigningAlgo *jwt.SigningMethodRSA
type PolicyFunc func(c *Claims)
type PermFunc func(c *Claims) error

var (
	RS256 = jwt.SigningMethodRS256
	RS384 = jwt.SigningMethodRS384
	RS512 = jwt.SigningMethodRS512
)

type Token struct {
	*jwt.Token
}

type Claims struct {
	*jwt.StandardClaims
	Renewed int `json:"renewed"`
}
