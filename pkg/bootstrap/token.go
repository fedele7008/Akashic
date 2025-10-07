package bootstrap

import (
	"akashic/akashic/pkg/database/redis"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"go.uber.org/zap"
)

const (
	// tokenKey is the Redis key for storing the bootstrap token
	tokenKey = "akashic:bootstrap:token"

	// tokenLength is the length of the token in bytes (32 bytes = 64 hex characters)
	tokenLength = 32
)

// TokenManager handles bootstrap token generation and validation
type TokenManager struct {
	redis  *redis.Client
	ttl    time.Duration
	logger *zap.Logger
}

// NewTokenManager creates a new token manager
func NewTokenManager(redis *redis.Client, ttl time.Duration, logger *zap.Logger) *TokenManager {
	return &TokenManager{
		redis:  redis,
		ttl:    ttl,
		logger: logger,
	}
}

// Generate creates a new bootstrap token and stores it in Redis
// This operation is atomic - it replaces any existing token
func (m *TokenManager) Generate(ctx context.Context) (string, error) {
	token, err := generateSecureToken(tokenLength)
	if err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}

	// Store in Redis with TTL (atomic replacement of old token)
	if err := m.redis.Set(ctx, tokenKey, token, m.ttl).Err(); err != nil {
		return "", fmt.Errorf("failed to store token in redis: %w", err)
	}

	m.logger.Info("Bootstrap token generated",
		zap.Duration("ttl", m.ttl),
		zap.Time("expires_at", time.Now().Add(m.ttl)))

	return token, nil
}

// Validate checks if the provided token matches the stored token
func (m *TokenManager) Validate(ctx context.Context, token string) (bool, error) {
	if token == "" {
		return false, nil
	}

	storedToken, err := m.redis.Get(ctx, tokenKey).Result()
	if err != nil {
		// Token doesn't exist or has expired
		if err.Error() == "redis: nil" {
			m.logger.Debug("Bootstrap token not found or expired")
			return false, nil
		}
		return false, fmt.Errorf("failed to get token from redis: %w", err)
	}

	// Constant-time comparison to prevent timing attacks
	valid := token == storedToken

	if !valid {
		m.logger.Warn("Invalid bootstrap token attempt")
	}

	return valid, nil
}

// Get retrieves the current bootstrap token (CLI only)
func (m *TokenManager) Get(ctx context.Context) (string, error) {
	token, err := m.redis.Get(ctx, tokenKey).Result()
	if err != nil {
		if err.Error() == "redis: nil" {
			return "", fmt.Errorf("bootstrap token not found or expired")
		}
		return "", fmt.Errorf("failed to get token: %w", err)
	}

	// Get TTL for the token
	ttl, err := m.redis.TTL(ctx, tokenKey).Result()
	if err == nil && ttl > 0 {
		m.logger.Debug("Bootstrap token retrieved",
			zap.Duration("remaining_ttl", ttl))
	}

	return token, nil
}

// Delete removes the bootstrap token from Redis
func (m *TokenManager) Delete(ctx context.Context) error {
	deleted, err := m.redis.Del(ctx, tokenKey).Result()
	if err != nil {
		return fmt.Errorf("failed to delete token: %w", err)
	}

	if deleted > 0 {
		m.logger.Info("Bootstrap token deleted")
	}

	return nil
}

// Exists checks if a bootstrap token currently exists
func (m *TokenManager) Exists(ctx context.Context) (bool, error) {
	exists, err := m.redis.Exists(ctx, tokenKey).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check token existence: %w", err)
	}

	return exists > 0, nil
}

// GetTTL returns the remaining time-to-live for the current token
func (m *TokenManager) GetTTL(ctx context.Context) (time.Duration, error) {
	ttl, err := m.redis.TTL(ctx, tokenKey).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to get token TTL: %w", err)
	}

	if ttl < 0 {
		return 0, fmt.Errorf("token not found or has no expiration")
	}

	return ttl, nil
}

// generateSecureToken generates a cryptographically secure random token
func generateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Convert to hex string (doubles the length in characters)
	return hex.EncodeToString(bytes), nil
}
