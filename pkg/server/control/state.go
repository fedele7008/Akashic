package control

import (
	"akashic/akashic/pkg/logging"
	"akashic/akashic/pkg/server/auth"
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// AuthServerState represents the state of the auth server
type AuthServerState int

const (
	_ AuthServerState = iota
	StateStopped
	StateStarting
	StateRunning
	StateStopping
	StateError
)

// String returns the string representation of the state
func (s AuthServerState) String() string {
	switch s {
	case StateStopped:
		return "stopped"
	case StateStarting:
		return "starting"
	case StateRunning:
		return "running"
	case StateStopping:
		return "stopping"
	case StateError:
		return "error"
	default:
		return "unknown"
	}
}

// StateManager manages the lifecycle of the auth server
type StateManager struct {
	mu           sync.RWMutex
	state        AuthServerState
	authServer   *auth.Server
	logger       *logging.Logger
	startedAt    time.Time
	errorMessage string
}

// NewStateManager creates a new state manager
func NewStateManager(authServer *auth.Server, logger *logging.Logger) *StateManager {
	initialState := StateStopped
	if authServer.IsRunning() {
		initialState = StateRunning
	}

	return &StateManager{
		authServer: authServer,
		logger:     logger,
		state:      initialState,
	}
}

// GetState returns the current state
func (sm *StateManager) GetState() AuthServerState {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.state
}

// GetStatus returns detailed status information
func (sm *StateManager) GetStatus() map[string]any {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	status := map[string]any{
		"state": sm.state.String(),
	}

	if sm.state == StateRunning {
		status["uptime"] = time.Since(sm.startedAt).String()
		status["started_at"] = sm.startedAt.Format(time.RFC3339)
		status["address"] = sm.authServer.GetAddress()
	}

	if sm.state == StateError {
		status["error"] = sm.errorMessage
	}

	return status
}

// Start starts the auth server
func (sm *StateManager) Start(ctx context.Context) error {
	sm.mu.Lock()

	// Check current state
	switch sm.state {
	case StateRunning:
		sm.mu.Unlock()
		return fmt.Errorf("auth server is already running")
	case StateStarting:
		sm.mu.Unlock()
		return fmt.Errorf("auth server is already starting")
	case StateStopping:
		sm.mu.Unlock()
		return fmt.Errorf("auth server is currently stopping, please wait")
	}

	// Transition to starting
	sm.state = StateStarting
	sm.errorMessage = ""
	sm.mu.Unlock()

	sm.logger.App.Info("Starting auth server")

	// Attempt to start
	if err := sm.authServer.Start(ctx); err != nil {
		sm.mu.Lock()
		sm.state = StateError
		sm.errorMessage = err.Error()
		sm.mu.Unlock()

		sm.logger.App.Error("Failed to start auth server", zap.Error(err))
		return fmt.Errorf("failed to start auth server: %v", err)
	}

	// Success
	sm.mu.Lock()
	sm.state = StateRunning
	sm.startedAt = time.Now()
	sm.mu.Unlock()

	sm.logger.App.Info("Auth server started successfully")
	return nil
}

// Stop stops the auth server
func (sm *StateManager) Stop() error {
	sm.mu.Lock()

	// Check current state
	switch sm.state {
	case StateStopped:
		sm.mu.Unlock()
		return fmt.Errorf("auth server is already stopped")
	case StateStarting:
		sm.mu.Unlock()
		return fmt.Errorf("auth server is starting, cannot stop yet")
	case StateStopping:
		sm.mu.Unlock()
		return fmt.Errorf("auth server is already stopping")
	case StateError:
		// Allow stopping from error state
		sm.state = StateStopped
		sm.mu.Unlock()
		return nil
	}

	// Transition to stopping
	sm.state = StateStopping
	sm.mu.Unlock()

	sm.logger.App.Info("Stopping auth server")

	// Attempt to stop
	if err := sm.authServer.Stop(); err != nil {
		sm.mu.Lock()
		sm.state = StateError
		sm.errorMessage = err.Error()
		sm.mu.Unlock()

		sm.logger.App.Error("Failed to stop auth server", zap.Error(err))
		return fmt.Errorf("failed to stop auth server: %v", err)
	}

	// Success
	sm.mu.Lock()
	sm.state = StateStopped
	sm.mu.Unlock()

	sm.logger.App.Info("Auth server stopped successfully")
	return nil
}

// Restart restarts the auth server
func (sm *StateManager) Restart(ctx context.Context) error {
	sm.logger.App.Info("Restarting auth server")

	// Stop if running
	currentState := sm.GetState()
	if currentState == StateRunning || currentState == StateError {
		if err := sm.Stop(); err != nil && currentState != StateError {
			return fmt.Errorf("failed to stop during restart: %v", err)
		}

		// Wait a moment for clean shutdown
		time.Sleep(500 * time.Millisecond)
	} else if currentState != StateStopped {
		return fmt.Errorf("cannot restart from state: %s", currentState.String())
	}

	// Start
	return sm.Start(ctx)
}
