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

	// TLS (Phase 4)
	TLSEnabled    bool
	TLSCACertPath string
	TLSServerName string
}

// DB wraps gorm.DB with additional functionality
type DB struct {
	*gorm.DB
	logger *logging.Logger
}

// New creates a new GORM database connection
func New(configMgr *config.ConfigManager, akashicLogger *logging.Logger) (*DB, error) {
	mConfig := configMgr.GetConfig()
	pg := mConfig.Database.Postgres
	cfg := Config{
		Host:            pg.Host,
		Port:            pg.Port,
		Database:        pg.Database,
		Username:        pg.Username,
		Password:        pg.Password,
		SSLMode:         pg.SSLMode,
		MaxConns:        pg.MaxConnections,
		MaxIdleConns:    pg.MaxIdleConnections,
		ConnLifetime:    pg.ConnectionLifetime,
		ConnMaxIdleTime: 30 * time.Minute,
		TLSEnabled:      pg.TLS.Enabled,
		TLSCACertPath:   pg.TLS.CACertPath,
		TLSServerName:   pg.TLS.ServerName,
	}

	dsn := buildDSN(&cfg)

	akashicLogger.App.Info("Connecting to PostgreSQL",
		zap.String("host", cfg.Host),
		zap.Int("port", cfg.Port),
		zap.String("database", cfg.Database),
		zap.String("user", cfg.Username),
		zap.Bool("tls", cfg.TLSEnabled),
		zap.String("sslmode", effectiveSSLMode(&cfg)))

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
		// Phase 7: registered client services (built-in akashic-admin +
		// future tenant-registered services). Table: client_services.
		// Schema lives in pkg/models/client_service.go.
		&models.ClientService{},
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

// effectiveSSLMode returns "disable" when TLS is off regardless of the configured
// SSLMode (so an operator who forgot to flip ssl_mode back when toggling TLS off
// still gets a plain connection instead of a dial failure).
func effectiveSSLMode(cfg *Config) string {
	if !cfg.TLSEnabled {
		return "disable"
	}
	if cfg.SSLMode == "" || cfg.SSLMode == "disable" {
		return "verify-full"
	}
	return cfg.SSLMode
}

// buildDSN assembles the libpq-style connection string. sslrootcert is only
// included when TLS is enabled; some driver versions reject the parameter when
// sslmode=disable.
func buildDSN(cfg *Config) string {
	dsn := fmt.Sprintf(
		"host=%s port=%d dbname=%s user=%s password=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.Database, cfg.Username, cfg.Password, effectiveSSLMode(cfg),
	)
	if cfg.TLSEnabled && cfg.TLSCACertPath != "" {
		dsn += fmt.Sprintf(" sslrootcert=%s", cfg.TLSCACertPath)
	}
	return dsn
}
