package ldap

import (
	"crypto/tls"

	"github.com/mickep76/auth"

	"github.com/pkg/errors"
	"gopkg.in/ldap.v2"
)

type driver struct {
	domain string
	base   string
	tls    *tls.Config
}

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

func (d *driver) Open(endpoints []string) (auth.Conn, error) {
	c, err := ldap.Dial("tcp", endpoints[0])
	if err != nil {
		return nil, errors.Wrapf(err, "ldap dial: %s", endpoints[0])
	}

	if d.tls != nil {
		if err := c.StartTLS(d.tls); err != nil {
			return nil, errors.Wrap(err, "ldap start tls")
		}
	}

	return &conn{
		domain: d.domain,
		base:   d.base,
		Conn:   c,
	}, nil
}

func init() {
	auth.Register("ldap", &driver{})
}
