package main

import (
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/mickep76/auth"
	_ "github.com/mickep76/auth/ldap"
)

type Handler struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	expiration time.Duration
	conn       auth.Conn
}

type Login struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func writeError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	w.Write([]byte(err.Error()))
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	l := Login{}
	if err := json.NewDecoder(r.Body).Decode(l); err != nil {
		writeError(w, err)
		return
	}

	u, err := h.conn.Login(l.Username, l.Password)
	if err != nil {
		writeError(w, err)
		return
	}

	t, err := u.Token(h.privateKey, h.expiration)
	if err != nil {
		writeError(w, err)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(t))
}

func (h *Handler) Options(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "GET,HEAD,OPTIONS,POST,PUT,PATCH,DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization")
	w.WriteHeader(http.StatusOK)
}

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

	// Create TLS config.
	cfg := &tls.Config{
		InsecureSkipVerify: *insecure,
		ServerName:         *server, // Send SNI (Server Name Indication) for host that serves multiple aliases.
	}

	// Create new auth connection.
	c, err := auth.Open("ldap", []string{*server}, auth.TLS(cfg), auth.Domain(*domain), auth.Base(*base))
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	// Load RSA private key.
	_, err = auth.LoadPrivKey(*privKey)
	if err != nil {
		log.Fatal(err)
	}

	// Load RSA public key.
	_, err = auth.LoadPubKey(*pubKey)
	if err != nil {
		log.Fatal(err)
	}

	// New router
	router := mux.NewRouter()

	// Handlers
	h := Handler{
		expiration: time.Duration(24) * time.Hour,
		conn:       c,
	}

	router.HandleFunc("/login", h.Login).Methods("POST")
	router.HandleFunc("/login", h.Options).Methods("OPTIONS")

	logr := handlers.LoggingHandler(os.Stdout, router)
	if err := http.ListenAndServeTLS(*bind, *cert, *key, logr); err != nil {
		log.Fatal("http listener:", err)
	}
}
