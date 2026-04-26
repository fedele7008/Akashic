package admin_bff

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
)

// Phase 7: minimal Redis client for the BFF's session store.
//
// The akashic-server has its own Redis client (pkg/database/akashic_redis)
// with health/stats/etc.; we deliberately don't import it here because
// the BFF is a separate process with simpler needs (one session-store
// namespace, no shared logging/config plumbing). A 60-line file is
// cheaper than dragging the server's wider deps into the BFF.
//
// TLS is enabled when AKASHIC_BFF_REDIS_TLS_CA is set. The CA path
// points at the same internal CA bundle Vault Agent renders for
// other services -- the operator passes /certs/redis/ca.crt (or the
// equivalent host-run path) and we trust whatever the bundle vouches
// for.

func newRedisClient(cfg *Config) (*redis.Client, error) {
	opts := &redis.Options{
		Addr:         cfg.RedisAddr,
		Password:     cfg.RedisPassword,
		DB:           cfg.RedisDB,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		PoolSize:     10,
		MinIdleConns: 2,
	}

	if cfg.RedisTLSCAFile != "" {
		tlsCfg, err := buildRedisTLSConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("redis tls config: %w", err)
		}
		opts.TLSConfig = tlsCfg
	}

	rdb := redis.NewClient(opts)

	// Eager ping so a misconfigured Redis fails BFF startup loudly,
	// not later inside an OAuth callback handler.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		_ = rdb.Close()
		return nil, fmt.Errorf("redis ping %s: %w", cfg.RedisAddr, err)
	}
	return rdb, nil
}

// buildRedisTLSConfig builds a tls.Config that trusts the supplied CA
// bundle. ServerName defaults to the host portion of RedisAddr so that
// hostname verification matches the cert SANs (Vault issues redis cert
// for redis.akashic.local etc.).
func buildRedisTLSConfig(cfg *Config) (*tls.Config, error) {
	pem, err := os.ReadFile(cfg.RedisTLSCAFile)
	if err != nil {
		return nil, fmt.Errorf("read redis CA bundle %s: %w", cfg.RedisTLSCAFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("redis CA bundle %s contained no usable certificates", cfg.RedisTLSCAFile)
	}

	serverName := cfg.RedisTLSServerName
	if serverName == "" {
		// Default: strip ":port" off RedisAddr.
		host := cfg.RedisAddr
		for i := len(host) - 1; i >= 0; i-- {
			if host[i] == ':' {
				host = host[:i]
				break
			}
		}
		serverName = host
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: serverName,
		RootCAs:    pool,
	}, nil
}
