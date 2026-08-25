package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/sverdlovsky/yet-another-oauth-endpoint/api/internal/authapp"
	"github.com/sverdlovsky/yet-another-oauth-endpoint/api/internal/config"
	"github.com/sverdlovsky/yet-another-oauth-endpoint/api/internal/registers"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}

	a := authapp.New(cfg.Domain, cfg.SecretKey, cfg.JWTSecret)

	mux := http.NewServeMux()

	if registers.RegisterGoogle(mux, a, cfg.GoogleClientID, cfg.GoogleClientSecret) {
		log.Println("provider enabled: google")
	} else {
		log.Println("provider disabled: google (GOOGLE_CLIENT_ID/SECRET not set)")
	}

	if registers.RegisterYandex(mux, a, cfg.YandexClientID, cfg.YandexClientSecret) {
		log.Println("provider enabled: yandex")
	} else {
		log.Println("provider disabled: yandex (YANDEX_CLIENT_ID/SECRET not set)")
	}

	var rdb *redis.Client
	if cfg.RedisAddr() != "" {
		rdb = redis.NewClient(&redis.Options{Addr: cfg.RedisAddr()})
	}

	if registers.RegisterEmail(mux, a, rdb, cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPFrom) {
		log.Println("provider enabled: email")
	} else {
		log.Println("provider disabled: email (REDIS_HOST/SMTP_HOST/SMTP_FROM not set)")
	}

	srv := &http.Server{
		Addr:         cfg.ListenAddr,
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

	log.Printf("listening on %s", cfg.ListenAddr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

