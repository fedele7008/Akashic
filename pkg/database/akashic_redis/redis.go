package akashic_redis

import (
	"akashic/akashic/pkg/config"
	"akashic/akashic/pkg/logging"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// Config holds Redis connection configuration
type Config struct {
	Host         string
	Port         int
	Password     string
	DB           int
	PoolSize     int
	MinIdleConns int
	MaxRetries   int
	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	// TLS (Phase 4)
	TLSEnabled    bool
	TLSCACertPath string
	TLSServerName string
	TLSSkipVerify bool
}

// Client wraps redis.Client with additional functionality
type Client struct {
	*redis.Client
	logger *logging.Logger
}

// New creates a new Redis client connection
func New(configMgr *config.ConfigManager, logger *logging.Logger) (*Client, error) {
	mConfig := configMgr.GetConfig()
	rCfg := mConfig.Database.Redis
	cfg := Config{
		Host:          rCfg.Host,
		Port:          rCfg.Port,
		Password:      rCfg.Password,
		DB:            rCfg.DB,
		PoolSize:      rCfg.PoolSize,
		MinIdleConns:  2,
		MaxRetries:    3,
		DialTimeout:   5 * time.Second,
		ReadTimeout:   3 * time.Second,
		WriteTimeout:  3 * time.Second,
		TLSEnabled:    rCfg.TLS.Enabled,
		TLSCACertPath: rCfg.TLS.CACertPath,
		TLSServerName: rCfg.TLS.ServerName,
		TLSSkipVerify: rCfg.TLS.SkipVerify,
	}

	logger.App.Info("Connecting to Redis",
		zap.String("host", cfg.Host),
		zap.Int("port", cfg.Port),
		zap.Int("database", cfg.DB),
		zap.Bool("tls", cfg.TLSEnabled))

	opts := &redis.Options{
		Addr:         fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Password:     cfg.Password,
		DB:           cfg.DB,
		PoolSize:     cfg.PoolSize,
		MinIdleConns: cfg.MinIdleConns,
		MaxRetries:   cfg.MaxRetries,
		DialTimeout:  cfg.DialTimeout,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	}
	if cfg.TLSEnabled {
		tlsCfg, err := buildTLSConfig(&cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to build Redis TLS config: %v", err)
		}
		opts.TLSConfig = tlsCfg
	}
	rdb := redis.NewClient(opts)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		rdb.Close()
		return nil, fmt.Errorf("failed to ping redis: %v", err)
	}

	logger.App.Info("Redis connection established successfully",
		zap.Int("pool_size", cfg.PoolSize),
		zap.Int("min_idle_conns", cfg.MinIdleConns))

	return &Client{Client: rdb, logger: logger}, nil
}

// Health checks the Redis connection health
func (c *Client) Health(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	if err := c.Ping(ctx).Err(); err != nil {
		c.logger.App.Warn("Redis health check failed", zap.Error(err))
		return fmt.Errorf("redis health check failed: %v", err)
	}

	return nil
}

// Close closes the Redis client connection
func (c *Client) Close() error {
	c.logger.App.Info("Closing Redis connection")
	return c.Client.Close()
}

// GetStats returns Redis pool statistics
func (c *Client) GetStats() *redis.PoolStats {
	return c.PoolStats()
}

// buildTLSConfig constructs the tls.Config used by the Redis client.
// When SkipVerify is false (the expected case), the CA bundle must be readable
// and parse as PEM — otherwise we fail fast rather than silently falling back
// to the system trust store.
func buildTLSConfig(cfg *Config) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         firstNonEmpty(cfg.TLSServerName, cfg.Host),
		InsecureSkipVerify: cfg.TLSSkipVerify,
	}
	if !cfg.TLSSkipVerify {
		if cfg.TLSCACertPath == "" {
			return nil, fmt.Errorf("redis TLS enabled but ca_cert path is empty")
		}
		pem, err := os.ReadFile(cfg.TLSCACertPath)
		if err != nil {
			return nil, fmt.Errorf("read redis CA bundle %s: %v", cfg.TLSCACertPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("redis CA bundle %s contained no valid certificates", cfg.TLSCACertPath)
		}
		tlsCfg.RootCAs = pool
	}
	return tlsCfg, nil
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
