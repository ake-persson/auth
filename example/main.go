package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/mickep76/auth"
	_ "github.com/mickep76/auth/ldap"
	"github.com/mickep76/tlscfg"
)

func main() {
	server := flag.String("server", "ldap", "LDAP server.")
	insecure := flag.Bool("insecure", false, "Insecure TLS.")
	port := flag.Int("port", 636, "LDAP port.")
	domain := flag.String("domain", "", "AD Domain.")
	base := flag.String("base", "", "LDAP Base.")
	flag.Parse()

	c := tlscfg.New(&tlscfg.Options{ServerName: *server, Insecure: *insecure})
	if err := c.Init(); err != nil {
		log.Fatal(err)
	}

	_, err := auth.Open("ldap", []string{fmt.Sprintf("%s:%d", *server, *port)}, auth.TLS(c.Config()), auth.Domain(*domain), auth.Base(*base))
	if err != nil {
		log.Fatal(err)
	}
}
