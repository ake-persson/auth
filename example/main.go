package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/mickep76/auth"
	"github.com/mickep76/auth/jwt"
	_ "github.com/mickep76/auth/ldap"
)

type Handler struct {
	jwt  *jwt.JWTServer
	conn auth.Conn
}

type Login struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

var setOperPolicy = jwt.PolicyFunc(func(c *jwt.Claims) {
	//	c.Roles = []string{"operator"}
})

var isAdminPerm = jwt.PermFunc(func(c *jwt.Claims) error {
	/*
		for _, r := range c.Roles {
			if r == "admin" {
				return nil
			}
		}
	*/
	return errors.New("need to be admin")
})

func writeError(w http.ResponseWriter, err error) {
	w.WriteHeader(http.StatusBadRequest)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
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

	t := h.jwt.NewToken(u, setOperPolicy())
	s, err := h.jwt.SignToken(t)
	if err != nil {
		writeError(w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(s))
}

func (h *Handler) Renew(w http.ResponseWriter, r *http.Request) {
	t, err := h.jwt.ParseTokenHeader(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(err.Error()))
		return
	}

	h.jwt.RenewToken(t)
	s, err := h.jwt.SignToken(t)
	if err != nil {
		writeError(w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(s))
}

func (h *Handler) Verify(w http.ResponseWriter, r *http.Request) {
	t, err := h.jwt.ParseTokenHeader(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(err.Error()))
		return
	}

	b, _ := json.MarshalIndent(t.Claims, "", "  ")

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Write(b)
}

func (h *Handler) Admin(w http.ResponseWriter, r *http.Request) {
	m := map[string]interface{}{"admin": true}
	b, _ := json.MarshalIndent(&m, "", "  ")

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Write(b)
}

func main() {
	backend := flag.String("backend", "ad", "Backend either ad or ldap.")
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
		ServerName:         strings.Split(*server, ":")[0], // Send SNI (Server Name Indication) for host that serves multiple aliases.
	}

	// Create new auth connection.
	c, err := auth.Open(*backend, []string{*server}, auth.WithTLS(cfg), auth.WithDomain(*domain), auth.WithBase(*base))
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	// Create JWT.
	j := jwt.NewJWTServer(jwt.RS512, time.Duration(24)*time.Hour, time.Duration(5)*time.Minute)

	// Load RSA private key.
	if err := j.LoadPrivateKey(*privKey); err != nil {
		log.Fatal(err)
	}

	// Load RSA public key.
	if err := j.LoadPublicKey(*pubKey); err != nil {
		log.Fatal(err)
	}

	// New router
	router := mux.NewRouter()

	// Handlers
	h := Handler{
		jwt:  j,
		conn: c,
	}

	router.HandleFunc("/login", h.Login).Methods("POST")
	router.HandleFunc("/renew", h.Renew).Methods("GET")
	router.HandleFunc("/verify", h.Verify).Methods("GET")
	router.Handle("/admin", j.Authorized(http.HandlerFunc(h.Admin), isAdminPerm)).Methods("GET")

	logr := handlers.LoggingHandler(os.Stdout, router)
	if err := http.ListenAndServeTLS(*bind, *cert, *key, logr); err != nil {
		log.Fatal("http listener:", err)
	}
}
