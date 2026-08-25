package config

import (
	"fmt"
	"os"
)

type Config struct {
	Domain    string
	SecretKey string
	JWTSecret string

	ListenAddr string

	GoogleClientID     string
	GoogleClientSecret string

	YandexClientID     string
	YandexClientSecret string

	RedisHost string
	RedisPort string

	SMTPHost string
	SMTPPort string
	SMTPFrom string
}

func Load() (*Config, error) {
	cfg := &Config{
		ListenAddr: getEnvDefault("LISTEN_ADDR", ":8080"),

		GoogleClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),

		YandexClientID:     os.Getenv("YANDEX_CLIENT_ID"),
		YandexClientSecret: os.Getenv("YANDEX_CLIENT_SECRET"),

		RedisHost: os.Getenv("REDIS_HOST"),
		RedisPort: getEnvDefault("REDIS_PORT", "6379"),

		SMTPHost: os.Getenv("SMTP_HOST"),
		SMTPPort: getEnvDefault("SMTP_PORT", "25"),
		SMTPFrom: os.Getenv("SMTP_FROM"),
	}

	required := map[string]*string{
		"DOMAIN":     &cfg.Domain,
		"SECRET_KEY": &cfg.SecretKey,
		"JWT_SECRET": &cfg.JWTSecret,
	}
	for name, dst := range required {
		v := os.Getenv(name)
		if v == "" {
			return nil, fmt.Errorf("missing required env var: %s", name)
		}
		*dst = v
	}

	return cfg, nil
}

func (c *Config) RedisAddr() string {
	if c.RedisHost == "" {
		return ""
	}
	return c.RedisHost + ":" + c.RedisPort
}

func getEnvDefault(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

