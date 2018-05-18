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
	user := flag.String("user", "", "LDAP User.")
	pass := flag.String("pass", "", "LDAP Password.")
	flag.Parse()

	cfg := tlscfg.New(&tlscfg.Options{ServerName: *server, Insecure: *insecure})
	if err := cfg.Init(); err != nil {
		log.Fatal(err)
	}

	c, err := auth.Open("ldap", []string{fmt.Sprintf("%s:%d", *server, *port)}, auth.TLS(cfg.Config()), auth.Domain(*domain), auth.Base(*base))
	if err != nil {
		log.Fatal(err)
	}

	u, err := c.Login(*user, *pass)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("User: %+v", u)
}
