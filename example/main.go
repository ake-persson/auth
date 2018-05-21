package main

import (
	"flag"
	"fmt"
	"log"

	"crypto/tls"

	"github.com/mickep76/auth"
	_ "github.com/mickep76/auth/ldap"
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

	cfg := &tls.Config{
		InsecureSkipVerify: *insecure,
		ServerName:         *server, // Send SNI (Server Name Indication) for host that serves multiple aliases.
	}

	c, err := auth.Open("ldap", []string{fmt.Sprintf("%s:%d", *server, *port)}, auth.TLS(cfg), auth.Domain(*domain), auth.Base(*base))
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	u, err := c.Login(*user, *pass)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("DN: %s\n", u.DN)
	fmt.Printf("Name: %s\n", u.Name)
	fmt.Printf("Username: %s\n", u.Username)
	fmt.Printf("Mail: %s\n", u.Mail)
	fmt.Print("Groups:\n\n")
	for _, g := range u.Groups {
		fmt.Printf("DN: %s\n", g.DN)
		fmt.Printf("Name: %s\n\n", g.Name)
	}
}
