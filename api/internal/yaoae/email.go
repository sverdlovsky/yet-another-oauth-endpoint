package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"time"

	"github.com/redis/go-redis/v9"
)

const magicLinkTTL = 10 * time.Minute

const redisKeyPrefix = "magic:"

type magicLinkPayload struct {
	Email string `json:"email"`
	Next  string `json:"next"`
}

func registerEmail(mux *http.ServeMux, a *app, rdb *redis.Client, smtpHost, smtpPort, smtpFrom string) bool {
	if rdb == nil || smtpHost == "" || smtpFrom == "" {
		return false
	}

	mailer := &smtpMailer{host: smtpHost, port: smtpPort, from: smtpFrom}

	ipLimiter := &rateLimiter{rdb: rdb, prefix: "ratelimit:email:ip:", limit: 10, window: time.Hour}
	emailLimiter := &rateLimiter{rdb: rdb, prefix: "ratelimit:email:addr:", limit: 3, window: time.Hour}

	mux.HandleFunc("GET /with/email", handleEmailRequest(a, rdb, mailer, ipLimiter, emailLimiter))
	mux.HandleFunc("GET /with/email/callback", handleEmailCallback(a, rdb))
	return true
}

func handleEmailRequest(a *app, rdb *redis.Client, mailer *smtpMailer, ipLimiter, emailLimiter *rateLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.canonicalRedirect(w, r) {
			return
		}

		email := r.URL.Query().Get("a")
		if email == "" {
			http.Error(w, "missing \"a\" query parameter", http.StatusBadRequest)
			return
		}
		if _, err := mail.ParseAddress(email); err != nil {
			http.Error(w, "invalid email address", http.StatusBadRequest)
			return
		}

		if !ipLimiter.allow(r.Context(), clientIP(r)) {
			tooManyRequests(w, "too many requests from this address, try again later")
			return
		}
		if !emailLimiter.allow(r.Context(), email) {
			tooManyRequests(w, "too many sign-in emails requested for this address, try again later")
			return
		}

		next := r.URL.Query().Get("next")
		if next == "" {
			next = "https://" + a.domain + "/"
		}

		code, err := randomState()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		payload, err := json.Marshal(magicLinkPayload{Email: email, Next: next})
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		key := redisKeyPrefix + hashCode(code)
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		if err := rdb.Set(ctx, key, payload, magicLinkTTL).Err(); err != nil {
			log.Printf("email: redis set failed: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		link := fmt.Sprintf("https://auth.%s/with/email/callback?c=%s", a.domain, code)
		if err := mailer.sendMagicLink(email, link); err != nil {
			log.Printf("email: failed to send mail to %s: %v", email, err)
			rdb.Del(ctx, key)
			http.Error(w, "failed to send email", http.StatusBadGateway)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Check your email for a sign-in link."))
	}
}

func handleEmailCallback(a *app, rdb *redis.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("c")
		if code == "" {
			http.Error(w, "missing \"c\" query parameter", http.StatusBadRequest)
			return
		}

		key := redisKeyPrefix + hashCode(code)
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()

		raw, err := rdb.Get(ctx, key).Result()
		if err == redis.Nil {
			http.Error(w, "link is invalid, expired, or already used", http.StatusUnauthorized)
			return
		}
		if err != nil {
			log.Printf("email: redis get failed: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		rdb.Del(ctx, key)

		var payload magicLinkPayload
		if err := json.Unmarshal([]byte(raw), &payload); err != nil {
			log.Printf("email: corrupt redis payload: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if err := a.issueSessionCookie(w, payload.Email, ""); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		next := payload.Next
		if next == "" {
			next = "https://" + a.domain + "/"
		}
		if u, err := url.Parse(next); err == nil {
			http.Redirect(w, r, u.String(), http.StatusFound)
			return
		}
		http.Redirect(w, r, "https://"+a.domain+"/", http.StatusFound)
	}
}

func hashCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

type smtpMailer struct {
	host string
	port string
	from string
}

func (m *smtpMailer) sendMagicLink(to, link string) error {
	addr := m.host + ":" + m.port

	subject := "Your sign-in link"
	body := fmt.Sprintf(
		"Click the link below to sign in. This link is valid for 10 minutes and can be used once.\r\n\r\n%s\r\n",
		link,
	)

	msg := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s",
		m.from, to, subject, body,
	)

	client, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer client.Close()

	if err := client.Mail(m.from); err != nil {
		return fmt.Errorf("MAIL FROM: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("RCPT TO: %w", err)
	}

	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA: %w", err)
	}
	if _, err := wc.Write([]byte(msg)); err != nil {
		wc.Close()
		return fmt.Errorf("write body: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("close body: %w", err)
	}

	return client.Quit()
}

