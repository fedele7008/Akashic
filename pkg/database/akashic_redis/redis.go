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
}

// Client wraps redis.Client with additional functionality
type Client struct {
	*redis.Client
	logger *logging.Logger
}

// New creates a new Redis client connection
func New(configMgr *config.ConfigManager, logger *logging.Logger) (*Client, error) {
	mConfig := configMgr.GetConfig()
	cfg := Config{
		Host:         mConfig.Database.Redis.Host,
		Port:         mConfig.Database.Redis.Port,
		Password:     mConfig.Database.Redis.Password,
		DB:           mConfig.Database.Redis.DB,
		PoolSize:     mConfig.Database.Redis.PoolSize,
		MinIdleConns: 2,
		MaxRetries:   3,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	}

	logger.App.Info("Connecting to Redis",
		zap.String("host", cfg.Host),
		zap.Int("port", cfg.Port),
		zap.Int("database", cfg.DB))

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

	// Configure TLS if enabled
	if mConfig.Database.Redis.TLS.Enabled {
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
		if mConfig.Database.Redis.TLS.CAFile != "" {
			caCert, err := os.ReadFile(mConfig.Database.Redis.TLS.CAFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read Redis CA cert: %v", err)
			}
			caPool := x509.NewCertPool()
			if !caPool.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("failed to parse Redis CA cert")
			}
			tlsConfig.RootCAs = caPool
		}
		opts.TLSConfig = tlsConfig
		logger.App.Info("Redis TLS enabled")
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
