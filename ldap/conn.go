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

type searchScope int

const (
	scopeBase searchScope = iota
	scopeOne
	scopeSub
)

func (c *conn) Login(user string, pass string) (*auth.User, error) {
	loginUser := user
	if c.domain != "" {
		loginUser = fmt.Sprintf("%s\\%s", c.domain, user)
	}

	if err := c.Bind(loginUser, pass); err != nil {
		return nil, errors.Wrapf(err, "ldap bind user: %s", loginUser)
	}

	u := &auth.User{
		Username: user,
	}

	entries, err := c.user(c.base, user, []string{"cn", "mail"})
	if err != nil {
		return nil, errors.Wrapf(err, "ldap search username: %s", user)
	}

	for _, e := range entries[0].Attributes {
		switch e.Name {
		case "cn":
			u.Name = e.Values[0]
		case "mail":
			u.Mail = e.Values[0]
		}
	}

	return u, nil
}

func (c *conn) search(base string, scope searchScope, query string, fields []string) ([]*ldap.Entry, error) {
	req := ldap.NewSearchRequest(base, int(scope), ldap.NeverDerefAliases, 0, 0, false, query, fields, nil)

	res, err := c.Search(req)
	if err != nil {
		return nil, err
	}

	return res.Entries, nil
}

func (c *conn) user(base string, user string, fields []string) ([]*ldap.Entry, error) {
	entries, err := c.search(base, scopeSub, fmt.Sprintf("(&(objectClass=user)(sAMAccountName=%s))", user), fields)
	if err != nil {
		return nil, err
	}

	return entries, nil
}

func (c *conn) memberOf(base string, dn string) ([]*ldap.Entry, error) {
	entries, err := c.search(base, scopeSub, fmt.Sprintf("(&(member=%s))", dn), []string{"dn"})
	if err != nil {
		return nil, err
	}

	return entries, nil
}

func (c *conn) Close() error {
	return c.Close()
}
