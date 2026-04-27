package control

import (
	"akashic/akashic/pkg/logging"
	"akashic/akashic/pkg/server/api"
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// APIStateManager manages the API server's lifecycle. Mirror of the
// existing StateManager that wraps the auth server — same state
// machine, same state names (the AuthServerState enum is reused),
// just pointing at a different server.
//
// We keep this as a parallel type rather than generifying StateManager
// because the cost of duplication is low (~60 lines) and the type
// safety of "this manager manages the API server, not the auth
// server" makes wiring less error-prone.
type APIStateManager struct {
	mu           sync.RWMutex
	state        AuthServerState
	apiServer    *api.Server
	logger       *logging.Logger
	startedAt    time.Time
	errorMessage string
}

func NewAPIStateManager(apiServer *api.Server, logger *logging.Logger) *APIStateManager {
	initialState := StateStopped
	if apiServer.IsRunning() {
		initialState = StateRunning
	}
	return &APIStateManager{
		apiServer: apiServer,
		logger:    logger,
		state:     initialState,
	}
}

// GetAPIServer exposes the managed api.Server for callers that need
// to operate on it directly (e.g. cert reload). Prefer state-aware
// methods (Start/Stop/Restart) when managing lifecycle.
func (m *APIStateManager) GetAPIServer() *api.Server {
	return m.apiServer
}

func (m *APIStateManager) GetState() AuthServerState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

func (m *APIStateManager) GetStatus() map[string]any {
	m.mu.RLock()
	defer m.mu.RUnlock()

	status := map[string]any{"state": m.state.String()}
	if m.state == StateRunning {
		status["uptime"] = time.Since(m.startedAt).String()
		status["started_at"] = m.startedAt.Format(time.RFC3339)
		status["address"] = m.apiServer.GetAddress()
	}
	if m.state == StateError {
		status["error"] = m.errorMessage
	}
	return status
}

func (m *APIStateManager) Start(ctx context.Context) error {
	m.mu.Lock()
	switch m.state {
	case StateRunning:
		m.mu.Unlock()
		return fmt.Errorf("api server is already running")
	case StateStarting:
		m.mu.Unlock()
		return fmt.Errorf("api server is already starting")
	case StateStopping:
		m.mu.Unlock()
		return fmt.Errorf("api server is currently stopping, please wait")
	}
	m.state = StateStarting
	m.errorMessage = ""
	m.mu.Unlock()

	m.logger.App.Info("Starting api server")
	if err := m.apiServer.Start(ctx); err != nil {
		m.mu.Lock()
		m.state = StateError
		m.errorMessage = err.Error()
		m.mu.Unlock()
		m.logger.App.Error("Failed to start api server", zap.Error(err))
		return fmt.Errorf("failed to start api server: %v", err)
	}
	m.mu.Lock()
	m.state = StateRunning
	m.startedAt = time.Now()
	m.mu.Unlock()
	m.logger.App.Info("API server started successfully")
	return nil
}

func (m *APIStateManager) Stop() error {
	m.mu.Lock()
	switch m.state {
	case StateStopped:
		m.mu.Unlock()
		return fmt.Errorf("api server is already stopped")
	case StateStarting:
		m.mu.Unlock()
		return fmt.Errorf("api server is starting, cannot stop yet")
	case StateStopping:
		m.mu.Unlock()
		return fmt.Errorf("api server is already stopping")
	case StateError:
		m.state = StateStopped
		m.mu.Unlock()
		return nil
	}
	m.state = StateStopping
	m.mu.Unlock()

	m.logger.App.Info("Stopping api server")
	if err := m.apiServer.Stop(); err != nil {
		m.mu.Lock()
		m.state = StateError
		m.errorMessage = err.Error()
		m.mu.Unlock()
		m.logger.App.Error("Failed to stop api server", zap.Error(err))
		return fmt.Errorf("failed to stop api server: %v", err)
	}
	m.mu.Lock()
	m.state = StateStopped
	m.mu.Unlock()
	m.logger.App.Info("API server stopped successfully")
	return nil
}

func (m *APIStateManager) Restart(ctx context.Context) error {
	m.logger.App.Info("Restarting api server")
	currentState := m.GetState()
	if currentState == StateRunning || currentState == StateError {
		if err := m.Stop(); err != nil && currentState != StateError {
			return fmt.Errorf("failed to stop during restart: %v", err)
		}
		time.Sleep(500 * time.Millisecond)
	} else if currentState != StateStopped {
		return fmt.Errorf("cannot restart from state: %s", currentState.String())
	}
	return m.Start(ctx)
}
