package gormdb

import (
	"akashic/akashic/pkg/models"
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Config holds GORM database configuration
type Config struct {
	Host            string
	Port            int
	Database        string
	Username        string
	Password        string
	SSLMode         string
	MaxConns        int
	MaxIdleConns    int
	ConnLifetime    time.Duration
	ConnMaxIdleTime time.Duration
}

// DB wraps gorm.DB with additional functionality
type DB struct {
	*gorm.DB
	logger *zap.Logger
}

// New creates a new GORM database connection
func New(cfg *Config, zapLogger *zap.Logger) (*DB, error) {
	dsn := fmt.Sprintf(
		"host=%s port=%d dbname=%s user=%s password=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.Database, cfg.Username, cfg.Password, cfg.SSLMode,
	)

	zapLogger.Info("Connecting to PostgreSQL with GORM",
		zap.String("host", cfg.Host),
		zap.Int("port", cfg.Port),
		zap.String("database", cfg.Database),
		zap.String("user", cfg.Username))

	// Configure GORM logger (silent in production, info in development)
	gormLogger := logger.Default.LogMode(logger.Silent)

	gormDB, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger:                 gormLogger,
		SkipDefaultTransaction: true, // Better performance
		PrepareStmt:            true, // Cached prepared statements
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Get underlying sql.DB to configure connection pool
	sqlDB, err := gormDB.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}

	// Set connection pool settings
	sqlDB.SetMaxOpenConns(cfg.MaxConns)
	sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
	sqlDB.SetConnMaxLifetime(cfg.ConnLifetime)
	if cfg.ConnMaxIdleTime > 0 {
		sqlDB.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)
	}

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := sqlDB.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	zapLogger.Info("PostgreSQL connection established successfully",
		zap.Int("max_open_conns", cfg.MaxConns),
		zap.Int("max_idle_conns", cfg.MaxIdleConns),
		zap.Duration("conn_lifetime", cfg.ConnLifetime))

	return &DB{DB: gormDB, logger: zapLogger}, nil
}

// AutoMigrate runs automatic migrations for all models
func (db *DB) AutoMigrate() error {
	db.logger.Info("Running automatic database migrations")

	// List of all models to migrate
	modelList := []interface{}{
		&models.User{},
		&models.BootstrapStatus{},
	}

	if err := db.DB.AutoMigrate(modelList...); err != nil {
		return fmt.Errorf("auto-migration failed: %w", err)
	}

	// Initialize bootstrap status row if it doesn't exist
	var count int64
	if err := db.DB.Model(&models.BootstrapStatus{}).Count(&count).Error; err != nil {
		return fmt.Errorf("failed to check bootstrap status: %w", err)
	}

	if count == 0 {
		db.logger.Info("Initializing bootstrap status table")
		bootstrapStatus := &models.BootstrapStatus{
			ID:         true,
			IsComplete: false,
		}
		if err := db.DB.Create(bootstrapStatus).Error; err != nil {
			return fmt.Errorf("failed to initialize bootstrap status: %w", err)
		}
	}

	db.logger.Info("Database schema is up-to-date")
	return nil
}

// Health checks the database connection health
func (db *DB) Health(ctx context.Context) error {
	sqlDB, err := db.DB.DB()
	if err != nil {
		return fmt.Errorf("failed to get sql.DB: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	if err := sqlDB.PingContext(ctx); err != nil {
		db.logger.Warn("Database health check failed", zap.Error(err))
		return fmt.Errorf("database health check failed: %w", err)
	}

	return nil
}

// Close closes the database connection
func (db *DB) Close() error {
	db.logger.Info("Closing PostgreSQL connection")
	sqlDB, err := db.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}
