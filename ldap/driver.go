package ldap

import (
	"crypto/tls"

	"github.com/mickep76/auth"

	"github.com/pkg/errors"
	"gopkg.in/ldap.v2"
)

type driver struct {
	name           string
	endpoint       string
	domain         string
	base           string
	ou             string
	filterUser     string
	filterMemberOf string
	tls            *tls.Config
}

const (
	filterUser       = "(&(objectClass=account)(uid=%s))"
	filterMemberOf   = "(&(objectClass=posixGroup)(member=%s))"
	filterUserAD     = "(&(objectClass=user)(sAMAccountName=%s))"
	filterMemberOfAD = "(&(objectClass=group)(groupType:1.2.840.113556.1.4.803:=2147483648)(member=%s))"
)

func (d *driver) SetTLS(tls *tls.Config) error {
	d.tls = tls
	return nil
}

func (d *driver) SetDomain(domain string) error {
	d.domain = domain
	return nil
}

func (d *driver) SetBase(base string) error {
	d.base = base
	return nil
}

func (d *driver) SetOU(ou string) error {
	d.ou = ou
	return nil
}

func (d *driver) SetFilterUser(filter string) error {
	d.filterUser = filter
	return nil
}

func (d *driver) SetFilterMemberOf(filter string) error {
	d.filterMemberOf = filter
	return nil
}

func (d *driver) Open(endpoints []string) (auth.Conn, error) {
	d.endpoint = endpoints[0]

	c, err := ldap.Dial("tcp", d.endpoint)
	if err != nil {
		return nil, errors.Wrapf(err, "ldap dial: %s", endpoints[0])
	}

	if d.tls != nil {
		if err := c.StartTLS(d.tls); err != nil {
			return nil, errors.Wrap(err, "ldap start tls")
		}
	}

	nc := &conn{
		driver: d,
		Conn:   c,
	}

	return nc, nil
}

func init() {
	auth.Register("ldap", &driver{
		name:           "ldap",
		filterUser:     filterUser,
		filterMemberOf: filterMemberOf,
	})
	auth.Register("ad", &driver{
		name:           "ad",
		filterUser:     filterUserAD,
		filterMemberOf: filterMemberOfAD,
	})
}
