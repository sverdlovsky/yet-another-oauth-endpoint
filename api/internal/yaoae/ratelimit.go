package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
)

type rateLimiter struct {
	rdb    *redis.Client
	prefix string
	limit  int64
	window time.Duration
}

func (rl *rateLimiter) allow(ctx context.Context, key string) bool {
	fullKey := rl.prefix + key

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	count, err := rl.rdb.Incr(ctx, fullKey).Result()
	if err != nil {
		return true
	}
	if count == 1 {
		rl.rdb.Expire(ctx, fullKey, rl.window)
	}

	return count <= rl.limit
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func tooManyRequests(w http.ResponseWriter, reason string) {
	http.Error(w, fmt.Sprintf("too many requests: %s", reason), http.StatusTooManyRequests)
}

