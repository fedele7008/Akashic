package common

import (
	"sync"
	"time"
)

type BreakerState int

const (
	BreakerClosed BreakerState = iota
	BreakerOpen
	BreakerHalfOpen
)

type Breaker struct {
	Mu       sync.Mutex
	state    BreakerState
	fails    int
	maxTries int
	cooldown time.Duration
	reopenAt time.Time

	// flag to allow only one routine to go try
	probeInFlight bool
}

func NewBreaker(maxTries int, cooldown time.Duration) *Breaker {
	if maxTries < 1 {
		maxTries = 1
	}
	if cooldown <= 0 {
		cooldown = 100 * time.Millisecond
	}
	return &Breaker{
		state:    BreakerClosed,
		maxTries: maxTries,
		cooldown: cooldown,
	}
}

func (b *Breaker) Allow() bool {
	now := time.Now()

	b.Mu.Lock()
	defer b.Mu.Unlock()

	switch b.state {
	case BreakerClosed:
		return true
	case BreakerOpen:
		// if cooldown time is over and no routine picked up request yet
		if now.After(b.reopenAt) && !b.probeInFlight {
			b.state = BreakerHalfOpen
			b.probeInFlight = true
			return true
		}
		return false
	case BreakerHalfOpen:
		// some routine is already on the request
		return false
	}
	return false
}

func (b *Breaker) OnSuccess() {
	b.Mu.Lock()
	defer b.Mu.Unlock()

	b.fails = 0

	switch b.state {
	case BreakerClosed:
		return
	case BreakerHalfOpen:
		b.state = BreakerClosed
		b.probeInFlight = false
	case BreakerOpen:
		// should not happen but it happens, act recovery
		if time.Now().After(b.reopenAt) {
			b.state = BreakerClosed
			b.probeInFlight = false
		}
	}
}
func (b *Breaker) OnFail() {
	now := time.Now()

	b.Mu.Lock()
	defer b.Mu.Unlock()

	switch b.state {
	case BreakerClosed:
		b.fails++
		if b.fails >= b.maxTries {
			b.state = BreakerOpen
			b.reopenAt = now.Add(b.cooldown)
			b.probeInFlight = false
		}
	case BreakerHalfOpen:
		// still service offline, extend cooldown time and go back to open state
		b.state = BreakerOpen
		b.reopenAt = now.Add(b.cooldown)
		b.probeInFlight = false
	case BreakerOpen:
		// should not happen but it happens, act recovery
		if now.After(b.reopenAt) {
			b.reopenAt = now.Add(b.cooldown)
		}
		b.probeInFlight = false
	}
}
