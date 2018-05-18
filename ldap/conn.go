package ldap

import (
	"fmt"

	"github.com/mickep76/auth"

	"github.com/pkg/errors"
	"gopkg.in/ldap.v2"
)

type conn struct {
	domain string
	base   string

	*ldap.Conn
}

func (c *conn) Login(user string, pass string) (*auth.User, error) {
	loginUser := user
	if c.domain != "" {
		loginUser = fmt.Sprintf("%s\\%s", c.domain, user)
	}

	if err := c.Bind(loginUser, pass); err != nil {
		return nil, errors.Wrapf(err, "ldap bind user: %s", loginUser)
	}

	return &auth.User{
		Username: user,
	}, nil
}

func (c *conn) Close() error {
	return c.Close()
}
