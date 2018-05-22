package ldap

import (
	"fmt"
	"strings"

	"github.com/mickep76/auth"

	"github.com/mickep76/qry/cnv"
	"github.com/pkg/errors"
	"gopkg.in/ldap.v2"
)

// TODO: Customize filters based on LDAP server like AD, OpenLDAP

const (
	filterUser     = "(&(objectClass=user)(sAMAccountName=%s))"
	filterMemberOf = "(&(member=%s))"
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
	if c.domain != "" {
		loginUser = fmt.Sprintf("%s\\%s", c.domain, user)
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

	entries, err := c.search(c.base, scopeSub, fmt.Sprintf(filterUser, user), []string{"cn", "mail", "uidNumber", "gidNumber", "homeDirectory", "loginShell"})
	if err != nil {
		return nil, errors.Wrapf(err, "ldap search username: %s", user)
	}

	u.DN = entries[0].DN
	for _, a := range entries[0].Attributes {
		switch a.Name {
		case "cn":
			u.Name = a.Values[0]
		case "mail":
			u.Mail = strings.ToLower(a.Values[0])
		case "uidNumber":
			cnv.ParseInt(a.Values[0], &u.UID)
		case "gidNumber":
			cnv.ParseInt(a.Values[0], &u.GID)
		case "homeDirectory":
			u.Home = a.Values[0]
		case "loginShell":
			u.Shell = a.Values[0]
		}
	}

	entries, err = c.search(c.base, scopeSub, fmt.Sprintf(filterMemberOf, u.DN), []string{"cn", "gidNumber"})
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
			case "gidNumber":
				cnv.ParseInt(a.Values[0], &u.GID)
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

func (c *conn) Close() error {
	return c.Close()
}
