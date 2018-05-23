package auth

import "crypto/tls"

var drivers = make(map[string]Driver)

type Driver interface {
	SetTLS(config *tls.Config) error
	SetDomain(domain string) error
	SetBase(base string) error
	SetFilterUser(filter string) error
	SetFilterMemberOf(filter string) error
	SetFilterMemberOfDistr(filter string) error
	Open(endpoints []string) (Conn, error)
}

func Register(name string, driver Driver) {
	drivers[name] = driver
}
