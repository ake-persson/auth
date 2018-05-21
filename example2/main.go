package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/mickep76/auth"
	_ "github.com/mickep76/auth/ldap"
)

func main() {
	bind := flag.String("bind", "0.0.0.0:8080", "Bind to address.")
	cert := flag.String("cert", "server.crt", "TLS HTTPS cert.")
	key := flag.String("key", "server.key", "TLS HTTPS key.")
	server := flag.String("server", "ldap:636", "LDAP server and port.")
	insecure := flag.Bool("insecure", false, "Insecure TLS.")
	domain := flag.String("domain", "", "AD Domain.")
	base := flag.String("base", "", "LDAP Base.")
	privKey := flag.String("priv-key", "private.rsa", "Private RSA key.")
	pubKey := flag.String("pub-key", "public.rsa", "Public RSA key.")
	flag.Parse()

	cfg := &tls.Config{
		InsecureSkipVerify: *insecure,
		ServerName:         *server, // Send SNI (Server Name Indication) for host that serves multiple aliases.
	}

	_, err := auth.Open("ldap", []string{*server}, auth.TLS(cfg), auth.Domain(*domain), auth.Base(*base))
	if err != nil {
		log.Fatal(err)
	}
	//	defer c.Close()

	_, err = auth.LoadPrivKey(*privKey)
	if err != nil {
		log.Fatal(err)
	}

	_, err = auth.LoadPubKey(*pubKey)
	if err != nil {
		log.Fatal(err)
	}

	// New router
	router := mux.NewRouter().StrictSlash(true)

	// Token handlers
	//	router.Handle("/", root.Get).Methods("GET")

	//	router.Handle("/token/issue", token.Issue).Methods("POST")
	//	router.Handle("/token/issue", token.Options).Methods("OPTIONS")

	//	router.Handle("/token/refresh", token.Refresh).Methods("POST")
	//	router.Handle("/token/refresh", token.Options).Methods("OPTIONS")

	//	router.Handle("/token/verify", token.Verify).Methods("GET")
	//	router.Handle("/token/verify", token.Options).Methods("OPTIONS")

	//	router.Handle("/rsa-pub-key", token.RSAPubKey).Methods("GET")
	//	router.Handle("/rsa-pub-key", token.Options).Methods("OPTIONS")

	logr := handlers.LoggingHandler(os.Stdout, router)
	if err := http.ListenAndServeTLS(*bind, *cert, *key, logr); err != nil {
		log.Fatal("http listener:", err)
	}
}
