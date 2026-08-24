package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/sessions"
	"github.com/redis/go-redis/v9"

	"github.com/sverdlovsky/yet-another-oauth-endpoint/internal/registers"
)

const sessionName = "session"

type app struct {
	domain       string
	jwtSecret    []byte
	sessionStore *sessions.CookieStore
}

func main() {
	domain := mustEnv("DOMAIN")
	secretKey := mustEnv("SECRET_KEY")
	jwtSecret := mustEnv("JWT_SECRET")

	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":8080"
	}

	googleClientID := os.Getenv("GOOGLE_CLIENT_ID")
	googleClientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")

	yandexClientID := os.Getenv("YANDEX_CLIENT_ID")
	yandexClientSecret := os.Getenv("YANDEX_CLIENT_SECRET")

	redisHost := os.Getenv("REDIS_HOST")
	redisPort := os.Getenv("REDIS_PORT")
	if redisPort == "" {
		redisPort = "6379"
	}

	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")
	if smtpPort == "" {
		smtpPort = "25"
	}
	smtpFrom := os.Getenv("SMTP_FROM")

	a := &app{
		domain:       domain,
		jwtSecret:    []byte(jwtSecret),
		sessionStore: newSessionStore(secretKey),
	}

	mux := http.NewServeMux()

	if registers.RegisterGoogle(mux, a, googleClientID, googleClientSecret) {
		log.Println("provider enabled: google")
	} else {
		log.Println("provider disabled: google (GOOGLE_CLIENT_ID/SECRET not set)")
	}

	if registers.RegisterYandex(mux, a, yandexClientID, yandexClientSecret) {
		log.Println("provider enabled: yandex")
	} else {
		log.Println("provider disabled: yandex (YANDEX_CLIENT_ID/SECRET not set)")
	}

	var rdb *redis.Client
	if redisHost != "" {
		rdb = redis.NewClient(&redis.Options{Addr: redisHost+":"+redisPort})
	}

	if registers.RegisterEmail(mux, a, rdb, smtpHost, smtpPort, smtpFrom) {
		log.Println("provider enabled: email")
	} else {
		log.Println("provider disabled: email (REDIS_ADDR/SMTP_HOST/SMTP_FROM not set)")
	}

	srv := &http.Server{
		Addr:         listenAddr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
		<-stop

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("graceful shutdown failed: %v", err)
		}
	}()

	log.Printf("listening on %s", listenAddr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func mustEnv(name string) string {
	v := os.Getenv(name)
	if v == "" {
		log.Fatalf("missing required env var: %s", name)
	}
	return v
}

func newSessionStore(secretKey string) *sessions.CookieStore {
	store := sessions.NewCookieStore([]byte(secretKey))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   int((30 * time.Minute).Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	return store
}

func (a *app) canonicalRedirect(w http.ResponseWriter, r *http.Request) bool {
	canonicalHost := "auth." + a.domain
	if r.Host == canonicalHost {
		return false
	}
	target := *r.URL
	target.Scheme = "https"
	target.Host = canonicalHost
	http.Redirect(w, r, target.String(), http.StatusFound)
	return true
}

func (a *app) popNext(sess *sessions.Session) string {
	next, _ := sess.Values["next"].(string)
	if next == "" {
		next = "https://" + a.domain + "/"
	}
	delete(sess.Values, "next")
	delete(sess.Values, "state")
	return next
}

func (a *app) issueSessionCookie(w http.ResponseWriter, sub, name string) error {
	claims := jwt.MapClaims{
		"sub":  sub,
		"name": name,
		"exp":  time.Now().Add(12 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(a.jwtSecret)
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    signed,
		Domain:   "." + a.domain,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	})
	return nil
}

func randomState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

