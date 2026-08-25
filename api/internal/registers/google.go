package registers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"golang.org/x/oauth2"
	xgoogle "golang.org/x/oauth2/google"

	"github.com/sverdlovsky/yet-another-oauth-endpoint/api/internal/authapp"
	"github.com/sverdlovsky/yet-another-oauth-endpoint/api/internal/randtoken"
)

func RegisterGoogle(mux *http.ServeMux, a *authapp.App, clientID, clientSecret string) bool {
	if clientID == "" || clientSecret == "" {
		return false
	}

	cfg := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     xgoogle.Endpoint,
		RedirectURL:  fmt.Sprintf("https://auth.%s/with/google/callback", a.Domain),
		Scopes:       []string{"openid", "email", "profile"},
	}

	mux.HandleFunc("GET /with/google", handleGoogleLogin(a, cfg))
	mux.HandleFunc("GET /with/google/callback", handleGoogleCallback(a, cfg))
	return true
}

func handleGoogleLogin(a *authapp.App, cfg *oauth2.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.CanonicalRedirect(w, r) {
			return
		}

		next := r.URL.Query().Get("next")
		if next == "" {
			next = "https://" + a.Domain + "/"
		}

		state, err := randtoken.New()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		sess, _ := a.SessionStore.Get(r, authapp.SessionName)
		sess.Values["state"] = state
		sess.Values["next"] = next
		if err := sess.Save(r, w); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, cfg.AuthCodeURL(state), http.StatusFound)
	}
}

func handleGoogleCallback(a *authapp.App, cfg *oauth2.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, _ := a.SessionStore.Get(r, authapp.SessionName)

		wantState, _ := sess.Values["state"].(string)
		gotState := r.URL.Query().Get("state")
		if wantState == "" || gotState == "" || gotState != wantState {
			http.Error(w, "invalid oauth state", http.StatusBadRequest)
			return
		}

		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "missing code", http.StatusBadRequest)
			return
		}

		ctx := context.Background()
		token, err := cfg.Exchange(ctx, code)
		if err != nil {
			log.Printf("google: token exchange failed: %v", err)
			http.Error(w, "token exchange failed", http.StatusBadGateway)
			return
		}

		email, name, err := fetchGoogleUser(ctx, cfg, token)
		if err != nil || email == "" {
			log.Printf("google: failed to fetch user info: %v", err)
			http.Error(w, "failed to fetch user info", http.StatusBadGateway)
			return
		}

		if err := a.IssueSessionCookie(w, email, name); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		next := a.PopNext(sess)
		if err := sess.Save(r, w); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if u, err := url.Parse(next); err == nil {
			http.Redirect(w, r, u.String(), http.StatusFound)
			return
		}
		http.Redirect(w, r, "https://"+a.Domain+"/", http.StatusFound)
	}
}

func fetchGoogleUser(ctx context.Context, cfg *oauth2.Config, token *oauth2.Token) (email, name string, err error) {
	client := cfg.Client(ctx, token)
	resp, err := client.Get("https://openidconnect.googleapis.com/v1/userinfo")
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	var raw struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return "", "", err
	}
	return raw.Email, raw.Name, nil
}

