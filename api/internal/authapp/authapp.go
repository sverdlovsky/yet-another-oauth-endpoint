package authapp

import (
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/sessions"
)

const SessionName = "session"

type App struct {
	Domain       string
	JWTSecret    []byte
	SessionStore *sessions.CookieStore
}

func New(domain, secretKey, jwtSecret string) *App {
	store := sessions.NewCookieStore([]byte(secretKey))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   int((30 * time.Minute).Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	return &App{
		Domain:       domain,
		JWTSecret:    []byte(jwtSecret),
		SessionStore: store,
	}
}

func (a *App) CanonicalRedirect(w http.ResponseWriter, r *http.Request) bool {
	canonicalHost := "auth." + a.Domain
	if r.Host == canonicalHost {
		return false
	}
	target := *r.URL
	target.Scheme = "https"
	target.Host = canonicalHost
	http.Redirect(w, r, target.String(), http.StatusFound)
	return true
}

func (a *App) PopNext(sess *sessions.Session) string {
	next, _ := sess.Values["next"].(string)
	if next == "" {
		next = "https://" + a.Domain + "/"
	}
	delete(sess.Values, "next")
	delete(sess.Values, "state")
	return next
}

func (a *App) IssueSessionCookie(w http.ResponseWriter, sub, name string) error {
	claims := jwt.MapClaims{
		"sub":  sub,
		"name": name,
		"exp":  time.Now().Add(12 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(a.JWTSecret)
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    signed,
		Domain:   "." + a.Domain,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	})
	return nil
}

