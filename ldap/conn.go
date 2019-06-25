package ldap

import (
	"fmt"
	"strings"

	"github.com/mickep76/auth"

	"github.com/pkg/errors"
	"gopkg.in/ldap.v2"
)

type conn struct {
	*driver
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

	if c.driver.name == "ad" && c.domain != "" {
		loginUser = fmt.Sprintf("%s\\%s", c.domain, user)
	} else if c.driver.name == "ldap" {
		loginUser = fmt.Sprintf("uid=%s,%s,%s", user, c.ou, c.base)
	}

	if err := c.Bind(loginUser, pass); err != nil {
		if ldap.IsErrorWithCode(err, ldap.ErrorNetwork) {
			// Retry
			nc, err := c.driver.Open([]string{c.endpoint})
			if err != nil {
				return nil, err
			}
			c = nc.(*conn)

			if err := c.Bind(loginUser, pass); err != nil {
				return nil, errors.Wrapf(err, "ldap bind user: %s", loginUser)
			}
		} else {
			return nil, errors.Wrapf(err, "ldap bind user: %s", loginUser)
		}
	}

	u := &auth.User{
		Username: user,
	}

	entries, err := c.search(c.base, scopeSub, fmt.Sprintf(c.filterUser, user), []string{"cn", "title", "description", "mail", "company", "department", "l", "st", "co"})
	if err != nil {
		return nil, errors.Wrapf(err, "ldap search username: %s", user)
	}

	if len(entries) == 0 {
		return nil, errors.Errorf("unknown user: %s", user)
	}

	if len(entries) > 1 {
		return nil, errors.Errorf("matched multiple accounts for user: %s", user)
	}

	dn := entries[0].DN
	for _, a := range entries[0].Attributes {
		switch a.Name {
		case "cn":
			u.Name = a.Values[0]
		case "title":
			u.Title = a.Values[0]
		case "description":
			u.Descr = a.Values[0]
		case "mail":
			u.Mail = strings.ToLower(a.Values[0])
		case "company":
			u.Company = a.Values[0]
		case "department":
			u.Department = a.Values[0]
		case "l":
			u.Location = a.Values[0]
		case "st":
			u.State = a.Values[0]
		case "co":
			u.Country = a.Values[0]
		}
	}

	entries, err = c.search(c.base, scopeSub, fmt.Sprintf(c.filterMemberOf, dn), []string{"cn"})
	if err != nil {
		return nil, errors.Wrapf(err, "ldap search user dn member of: %s", dn)
	}

	for _, e := range entries {
		for _, a := range e.Attributes {
			switch a.Name {
			case "cn":
				u.Groups = append(u.Groups, a.Values[0])
			}
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

func (c *conn) Close() error {
	return c.Close()
}
