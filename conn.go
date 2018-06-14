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

func TLS(tls *tls.Config) DriverOption {
	return func(d Driver) error {
		return d.SetTLS(tls)
	}
}

func DefaultTLS() DriverOption {
	return func(d Driver) error {
		return d.SetTLS(&tls.Config{})
	}
}

func Domain(domain string) DriverOption {
	return func(d Driver) error {
		return d.SetDomain(domain)
	}
}

func Base(base string) DriverOption {
	return func(d Driver) error {
		return d.SetBase(base)
	}
}

func FilterUser(filter string) DriverOption {
	return func(d Driver) error {
		return d.SetFilterUser(filter)
	}
}

func FilterMemberOf(filter string) DriverOption {
	return func(d Driver) error {
		return d.SetFilterMemberOf(filter)
	}
}

func FilterMemberOfDistr(filter string) DriverOption {
	return func(d Driver) error {
		return d.SetFilterMemberOfDistr(filter)
	}
}
