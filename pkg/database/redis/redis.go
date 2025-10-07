package redis

import (
	"context"
	"fmt"
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
	logger *zap.Logger
}

// New creates a new Redis client connection
func New(cfg *Config, logger *zap.Logger) (*Client, error) {
	logger.Info("Connecting to Redis",
		zap.String("host", cfg.Host),
		zap.Int("port", cfg.Port),
		zap.Int("db", cfg.DB))

	rdb := redis.NewClient(&redis.Options{
		Addr:         fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Password:     cfg.Password,
		DB:           cfg.DB,
		PoolSize:     cfg.PoolSize,
		MinIdleConns: cfg.MinIdleConns,
		MaxRetries:   cfg.MaxRetries,
		DialTimeout:  cfg.DialTimeout,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		rdb.Close()
		return nil, fmt.Errorf("failed to ping redis: %w", err)
	}

	logger.Info("Redis connection established successfully",
		zap.Int("pool_size", cfg.PoolSize),
		zap.Int("min_idle_conns", cfg.MinIdleConns))

	return &Client{Client: rdb, logger: logger}, nil
}

// Health checks the Redis connection health
func (c *Client) Health(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	if err := c.Ping(ctx).Err(); err != nil {
		c.logger.Warn("Redis health check failed", zap.Error(err))
		return fmt.Errorf("redis health check failed: %w", err)
	}

	return nil
}

// Close closes the Redis client connection
func (c *Client) Close() error {
	c.logger.Info("Closing Redis connection")
	return c.Client.Close()
}

// GetStats returns Redis pool statistics
func (c *Client) GetStats() *redis.PoolStats {
	return c.PoolStats()
}
