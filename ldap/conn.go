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

	u.DN = entries[0].DN
	for _, a := range entries[0].Attributes {
		switch a.Name {
		case "cn":
			u.Name = a.Values[0]
		case "mail":
			u.Mail = a.Values[0]
		}
	}

	entries, err = c.memberOf(c.base, u.DN, []string{"cn"})
	if err != nil {
		return nil, errors.Wrapf(err, "ldap search user dn member of: %s", u.DN)
	}

	groups := auth.Groups{}
	for _, e := range entries {
		for _, a := range e.Attributes {
			g := &auth.Group{
				DN: e.DN,
			}
			switch a.Name {
			case "cn":
				g.Name = a.Values[0]
			}
			groups = append(groups, g)
		}
	}
	u.Groups = groups

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

func (c *conn) memberOf(base string, dn string, fields []string) ([]*ldap.Entry, error) {
	entries, err := c.search(base, scopeSub, fmt.Sprintf("(&(member=%s))", dn), fields)
	if err != nil {
		return nil, err
	}

	return entries, nil
}

func (c *conn) Close() error {
	return c.Close()
}
