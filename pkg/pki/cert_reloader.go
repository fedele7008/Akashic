package pki

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"
)

const defaultCheckInterval = 30 * time.Second

// CertReloader watches certificate and key files for changes and reloads them automatically.
// It provides GetCertificate and GetClientCertificate callbacks for use with tls.Config.
type CertReloader struct {
	certPath string
	keyPath  string

	mu      sync.RWMutex
	cert    *tls.Certificate
	modTime time.Time

	logger   *zap.Logger
	cancel   context.CancelFunc
	interval time.Duration
}

// NewCertReloader creates a new CertReloader that watches the given cert and key files.
// It loads the certificate immediately and returns an error if the initial load fails.
func NewCertReloader(certPath, keyPath string, logger *zap.Logger) (*CertReloader, error) {
	cr := &CertReloader{
		certPath: certPath,
		keyPath:  keyPath,
		logger:   logger,
		interval: defaultCheckInterval,
	}

	if err := cr.reload(); err != nil {
		return nil, fmt.Errorf("initial certificate load failed: %w", err)
	}

	return cr, nil
}

// GetCertificate returns the current certificate for TLS server connections.
// This is intended to be used as tls.Config.GetCertificate callback.
func (cr *CertReloader) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cr.mu.RLock()
	defer cr.mu.RUnlock()
	return cr.cert, nil
}

// GetClientCertificate returns the current certificate for TLS client connections (mTLS).
// This is intended to be used as tls.Config.GetClientCertificate callback.
func (cr *CertReloader) GetClientCertificate(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	cr.mu.RLock()
	defer cr.mu.RUnlock()
	return cr.cert, nil
}

// Start begins the background file watcher that periodically checks for cert changes.
func (cr *CertReloader) Start(ctx context.Context) {
	watchCtx, cancel := context.WithCancel(ctx)
	cr.cancel = cancel

	go cr.watch(watchCtx)
}

// Stop stops the background file watcher.
func (cr *CertReloader) Stop() {
	if cr.cancel != nil {
		cr.cancel()
	}
}

func (cr *CertReloader) watch(ctx context.Context) {
	ticker := time.NewTicker(cr.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if cr.hasChanged() {
				if err := cr.reload(); err != nil {
					cr.logger.Error("Failed to reload certificate",
						zap.String("cert", cr.certPath),
						zap.Error(err))
				} else {
					cr.logger.Info("Certificate reloaded successfully",
						zap.String("cert", cr.certPath))
				}
			}
		}
	}
}

func (cr *CertReloader) hasChanged() bool {
	info, err := os.Stat(cr.certPath)
	if err != nil {
		return false
	}

	cr.mu.RLock()
	changed := info.ModTime().After(cr.modTime)
	cr.mu.RUnlock()

	return changed
}

func (cr *CertReloader) reload() error {
	cert, err := tls.LoadX509KeyPair(cr.certPath, cr.keyPath)
	if err != nil {
		return fmt.Errorf("failed to load certificate pair (%s, %s): %w", cr.certPath, cr.keyPath, err)
	}

	info, err := os.Stat(cr.certPath)
	if err != nil {
		return fmt.Errorf("failed to stat cert file: %w", err)
	}

	cr.mu.Lock()
	cr.cert = &cert
	cr.modTime = info.ModTime()
	cr.mu.Unlock()

	return nil
}
