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
	skew       time.Duration
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
	l := &Login{}
	if err := json.NewDecoder(r.Body).Decode(l); err != nil {
		writeError(w, err)
		return
	}
	defer r.Body.Close()

	u, err := h.conn.Login(l.Username, l.Password)
	if err != nil {
		writeError(w, err)
		return
	}

	s, err := auth.NewToken(u, h.expiration, h.skew).Sign(h.privateKey)
	if err != nil {
		writeError(w, err)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(s))
}

func (h *Handler) Renew(w http.ResponseWriter, r *http.Request) {
	t, err := auth.ParseTokenReader(r.Body, h.publicKey)
	if err != nil {
		writeError(w, err)
		return
	}
	defer r.Body.Close()

	s, err := t.Renew(h.expiration, h.skew).Sign(h.privateKey)
	if err != nil {
		writeError(w, err)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(s))
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
	privateKey, err := auth.LoadPrivateKey(*privKey)
	if err != nil {
		log.Fatal(err)
	}

	// Load RSA public key.
	publicKey, err := auth.LoadPublicKey(*pubKey)
	if err != nil {
		log.Fatal(err)
	}

	// New router
	router := mux.NewRouter()

	// Handlers
	h := Handler{
		privateKey: privateKey,
		publicKey:  publicKey,
		expiration: time.Duration(24) * time.Hour,
		skew:       time.Duration(5) * time.Minute,
		conn:       c,
	}

	router.HandleFunc("/renew", h.Renew).Methods("POST")
	router.HandleFunc("/login", h.Login).Methods("POST")
	//	router.HandleFunc("/verify", h.Login).Methods("POST")

	logr := handlers.LoggingHandler(os.Stdout, router)
	if err := http.ListenAndServeTLS(*bind, *cert, *key, logr); err != nil {
		log.Fatal("http listener:", err)
	}
}
