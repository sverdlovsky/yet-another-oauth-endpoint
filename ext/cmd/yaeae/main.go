package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const userEmailHeader = "X-User-Email"
const cookieName = "access_token"

func main() {
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("missing required env var: JWT_SECRET")
	}

	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":9001"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /frw/", authzHandler([]byte(jwtSecret)))

	srv := &http.Server {
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	log.Printf("ext_authz backend listening on %s", addr)
	log.Fatal(srv.ListenAndServe())
}

func authzHandler(jwtSecret []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		email, ok := verifyRequest(r, jwtSecret)
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set(userEmailHeader, email)
		w.WriteHeader(http.StatusOK)
	}
}

func verifyRequest(r *http.Request, jwtSecret []byte) (email string, ok bool) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		log.Printf("authz deny host=%q path=%q reason=no_cookie", r.Header.Get("X-Forwarded-Host"), r.URL.Path)
		return "", false
	}

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(cookie.Value, claims, func(t *jwt.Token) (interface{}, error) {
		if _, isHMAC := t.Method.(*jwt.SigningMethodHMAC); !isHMAC {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		log.Printf("authz deny reason=invalid_jwt err=%v", err)
		return "", false
	}

	sub, _ := claims["sub"].(string)
	if sub == "" {
		log.Printf("authz deny reason=empty_sub")
		return "", false
	}

	return sub, true
}

