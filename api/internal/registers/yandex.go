package registers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"golang.org/x/oauth2"

	"github.com/sverdlovsky/yet-another-oauth-endpoint/api/internal/authapp"
	"github.com/sverdlovsky/yet-another-oauth-endpoint/api/internal/randtoken"
)

var yandexEndpoint = oauth2.Endpoint{
	AuthURL:  "https://oauth.yandex.ru/authorize",
	TokenURL: "https://oauth.yandex.ru/token",
}

func RegisterYandex(mux *http.ServeMux, a *authapp.App, clientID, clientSecret string) bool {
	if clientID == "" || clientSecret == "" {
		return false
	}

	cfg := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     yandexEndpoint,
		RedirectURL:  fmt.Sprintf("https://auth.%s/with/yandex/callback", a.Domain),
		Scopes:       []string{"login:email", "login:info"},
	}

	mux.HandleFunc("GET /with/yandex", handleYandexLogin(a, cfg))
	mux.HandleFunc("GET /with/yandex/callback", handleYandexCallback(a, cfg))
	return true
}

func handleYandexLogin(a *authapp.App, cfg *oauth2.Config) http.HandlerFunc {
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

func handleYandexCallback(a *authapp.App, cfg *oauth2.Config) http.HandlerFunc {
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
			log.Printf("yandex: token exchange failed: %v", err)
			http.Error(w, "token exchange failed", http.StatusBadGateway)
			return
		}

		email, name, err := fetchYandexUser(ctx, token)
		if err != nil || email == "" {
			log.Printf("yandex: failed to fetch user info: %v", err)
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

func fetchYandexUser(ctx context.Context, token *oauth2.Token) (email, name string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://login.yandex.ru/info?format=json", nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Authorization", "OAuth "+token.AccessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	var raw struct {
		DefaultEmail string `json:"default_email"`
		Login        string `json:"login"`
		Name         string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return "", "", err
	}

	email = raw.DefaultEmail
	if email == "" {
		email = raw.Login
	}
	return email, raw.Name, nil
}

