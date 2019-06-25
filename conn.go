package auth

import (
	"crypto/tls"
	"fmt"
)

type Conn interface {
	Login(user string, pass string) (*User, error)
	Close() error
}

type DriverOption func(Driver) error

func Open(driver string, endpoints []string, options ...DriverOption) (Conn, error) {
	d, ok := drivers[driver]
	if !ok {
		return nil, fmt.Errorf("driver is not registered: %s", driver)
	}

	for _, option := range options {
		if err := option(d); err != nil {
			return nil, err
		}
	}

	return d.Open(endpoints)
}

func WithTLS(tls *tls.Config) DriverOption {
	return func(d Driver) error {
		return d.SetTLS(tls)
	}
}

func WithDomain(domain string) DriverOption {
	return func(d Driver) error {
		return d.SetDomain(domain)
	}
}

func WithBase(base string) DriverOption {
	return func(d Driver) error {
		return d.SetBase(base)
	}
}

func WithOU(ou string) DriverOption {
	return func(d Driver) error {
		return d.SetOU(ou)
	}
}

func WithFilterUser(filter string) DriverOption {
	return func(d Driver) error {
		return d.SetFilterUser(filter)
	}
}

func WithFilterMemberOf(filter string) DriverOption {
	return func(d Driver) error {
		return d.SetFilterMemberOf(filter)
	}
}
