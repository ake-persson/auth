package ldap

import (
	"fmt"

	"github.com/pkg/errors"
	"gopkg.in/ldap.v2"
)

type conn struct {
	domain string
	base   string

	*ldap.Conn
}

func (c *conn) Login(user string, pass string) error {
	loginUser := user
	if c.domain != "" {
		loginUser = fmt.Sprintf("%s\\%s", c.domain, user)
	}

	if err := c.Bind(loginUser, pass); err != nil {
		return errors.Wrapf(err, "ldap bind user: %s", loginUser)
	}

	return nil
}

func (c *conn) Close() error {
	return c.Close()
}
