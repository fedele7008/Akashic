package akashic_postgres

import (
	"akashic/akashic/pkg/config"
	"akashic/akashic/pkg/logging"
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
	logger *logging.Logger
}

// New creates a new GORM database connection
func New(configMgr *config.ConfigManager, akashicLogger *logging.Logger) (*DB, error) {
	mConfig := configMgr.GetConfig()
	cfg := Config{
		Host:            mConfig.Database.Postgres.Host,
		Port:            mConfig.Database.Postgres.Port,
		Database:        mConfig.Database.Postgres.Database,
		Username:        mConfig.Database.Postgres.Username,
		Password:        mConfig.Database.Postgres.Password,
		SSLMode:         mConfig.Database.Postgres.SSLMode,
		MaxConns:        mConfig.Database.Postgres.MaxConnections,
		MaxIdleConns:    mConfig.Database.Postgres.MaxIdleConnections,
		ConnLifetime:    mConfig.Database.Postgres.ConnectionLifetime,
		ConnMaxIdleTime: 30 * time.Minute,
	}

	dsn := fmt.Sprintf(
		"host=%s port=%d dbname=%s user=%s password=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.Database, cfg.Username, cfg.Password, cfg.SSLMode,
	)

	akashicLogger.App.Info("Connecting to PostgreSQL",
		zap.String("host", cfg.Host),
		zap.Int("port", cfg.Port),
		zap.String("database", cfg.Database),
		zap.String("user", cfg.Username))

	// Configure GORM logger (silent in production, warn in development)
	var gormLogger logger.Interface
	if mConfig.Deployment.Environment == config.EnvDevelopment {
		gormLogger = logger.Default.LogMode(logger.Warn)
	} else {
		gormLogger = logger.Default.LogMode(logger.Silent)
	}

	gormDB, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger:                 gormLogger,
		SkipDefaultTransaction: true, // Better performance
		PrepareStmt:            true, // Cached prepared statements
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %v", err)
	}

	// Get underlying sql.DB to configure connection pool
	sqlDB, err := gormDB.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get underlying sql.DB: %v", err)
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
		return nil, fmt.Errorf("failed to ping database: %v", err)
	}

	akashicLogger.App.Info("PostgreSQL connection established successfully",
		zap.Int("max_open_conns", cfg.MaxConns),
		zap.Int("max_idle_conns", cfg.MaxIdleConns),
		zap.Duration("conn_lifetime", cfg.ConnLifetime))

	return &DB{DB: gormDB, logger: akashicLogger}, nil
}

// AutoMigrate runs automatic migrations for all models
func (db *DB) AutoMigrate() error {
	db.logger.App.Info("Running automatic database migrations")

	// List of all models to migrate
	modelList := []any{
		&models.User{},
		&models.BootstrapStatus{},
	}

	if err := db.DB.AutoMigrate(modelList...); err != nil {
		return fmt.Errorf("auto-migration failed: %v", err)
	}

	// Initialize bootstrap status row if it doesn't exist
	var count int64
	if err := db.DB.Model(&models.BootstrapStatus{}).Count(&count).Error; err != nil {
		return fmt.Errorf("failed to check bootstrap status: %v", err)
	}

	if count == 0 {
		db.logger.App.Info("Initializing bootstrap status table")
		bootstrapStatus := &models.BootstrapStatus{
			ID:         true,
			IsComplete: false,
		}
		if err := db.DB.Create(bootstrapStatus).Error; err != nil {
			return fmt.Errorf("failed to initialize bootstrap status: %v", err)
		}
	}

	db.logger.App.Info("Database schema is up-to-date")
	return nil
}

// Health checks the database connection health
func (db *DB) Health(ctx context.Context) error {
	sqlDB, err := db.DB.DB()
	if err != nil {
		return fmt.Errorf("failed to get sql.DB: %v", err)
	}

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	if err := sqlDB.PingContext(ctx); err != nil {
		db.logger.App.Warn("Database health check failed", zap.Error(err))
		return fmt.Errorf("database health check failed: %v", err)
	}

	return nil
}

// Close closes the database connection
func (db *DB) Close() error {
	db.logger.App.Info("Closing PostgreSQL connection")
	sqlDB, err := db.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}
