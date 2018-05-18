package ldap

import (
	"gopkg.in/ldap.v2"
)

type conn struct {
	domain string
	base   string

	*ldap.Conn
}

func (c *conn) Close() error {
	return c.Close()
}
