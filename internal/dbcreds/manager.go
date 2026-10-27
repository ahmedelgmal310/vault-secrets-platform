// Package dbcreds manages dynamic database credentials from the Vault database
// secrets engine: it renews the lease while Vault allows it and, once the lease
// is capped by max_ttl or renewal fails, fetches a fresh username/password,
// hands it to the application and revokes the old lease.
package dbcreds

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/ahmedelgmal310/vault-secrets-platform/internal/vault"
)

// LeaseAPI is the subset of the Vault client the manager needs.
type LeaseAPI interface {
	Read(ctx context.Context, path string) (*vault.Secret, error)
	RenewLease(ctx context.Context, leaseID string, increment time.Duration) (*vault.Secret, error)
	RevokeLease(ctx context.Context, leaseID string) error
}

// Credential is one set of dynamic credentials.
type Credential struct {
	Username  string
	Password  string
	LeaseID   string
	TTL       time.Duration
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// Status is a snapshot that is safe to expose: it never contains the password.
type Status struct {
	Username         string    `json:"username"`
	IssuedAt         time.Time `json:"issued_at"`
	ExpiresAt        time.Time `json:"expires_at"`
	LeaseTTLSeconds  int       `json:"lease_ttl_seconds"`
	Renewals         int       `json:"renewals"`
	Rotations        int       `json:"rotations"`
	PreviousUsername string    `json:"previous_username,omitempty"`
	LastError        string    `json:"last_error,omitempty"`
}

// Manager owns the current credential.
type Manager struct {
	API  LeaseAPI
	Path string // e.g. database/creds/orders-api

	// OnRotate receives every new credential (including the first). It must
	// switch the application over, for example by replacing a connection pool.
	OnRotate func(context.Context, Credential) error

	Logger *slog.Logger
	Now    func() time.Time
	Sleep  func(context.Context, time.Duration) error

	mu        sync.Mutex
	cur       Credential
	increment time.Duration
	capped    bool
	renewals  int
	rotations int
	previous  string
	lastErr   string
}

func (m *Manager) defaults() {
	if m.Now == nil {
		m.Now = time.Now
	}
	if m.Sleep == nil {
		m.Sleep = vault.SleepContext
	}
	if m.Logger == nil {
		m.Logger = slog.Default()
	}
}

// Acquire fetches the first credential and hands it to OnRotate.
func (m *Manager) Acquire(ctx context.Context) error {
	m.defaults()
	c, err := m.fetch(ctx)
	if err != nil {
		return err
	}
	if err := m.OnRotate(ctx, c); err != nil {
		_ = m.API.RevokeLease(ctx, c.LeaseID)
		return fmt.Errorf("apply credential: %w", err)
	}
	m.mu.Lock()
	m.cur, m.increment, m.capped = c, c.TTL, false
	m.mu.Unlock()
	m.Logger.Info("database credential issued", "username", c.Username, "ttl", c.TTL.String())
	return nil
}

func (m *Manager) fetch(ctx context.Context) (Credential, error) {
	s, err := m.API.Read(ctx, m.Path)
	if err != nil {
		return Credential{}, err
	}
	c := Credential{
		Username: s.StringField("username"),
		Password: s.StringField("password"),
		LeaseID:  s.LeaseID,
		TTL:      s.TTL(),
		IssuedAt: m.Now(),
	}
	if c.Username == "" || c.Password == "" || c.LeaseID == "" || c.TTL <= 0 {
		return Credential{}, errors.New("vault returned an incomplete database credential")
	}
	c.ExpiresAt = c.IssuedAt.Add(c.TTL)
	return c, nil
}

// Run renews and rotates until ctx is cancelled.
func (m *Manager) Run(ctx context.Context) error {
	m.defaults()
	for {
		m.mu.Lock()
		wait := vault.RenewAfter(m.Now(), m.cur.ExpiresAt)
		capped := m.capped
		m.mu.Unlock()
		if err := m.Sleep(ctx, wait); err != nil {
			return err
		}
		if !capped && m.renew(ctx) {
			continue
		}
		if err := m.rotateWithRetry(ctx); err != nil {
			return err
		}
	}
}

// renew extends the lease. It reports false when the caller should rotate now.
func (m *Manager) renew(ctx context.Context) bool {
	m.mu.Lock()
	id, inc := m.cur.LeaseID, m.increment
	m.mu.Unlock()
	s, err := m.API.RenewLease(ctx, id, inc)
	if err != nil {
		m.setErr(err)
		m.Logger.Warn("database lease renewal failed, rotating", "error", err)
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cur.ExpiresAt = m.Now().Add(s.TTL())
	m.renewals++
	if s.TTL()+time.Second < inc {
		// Vault granted less than asked: max_ttl is near. Use the rest of the
		// lease, then rotate instead of renewing again.
		m.capped = true
	}
	m.Logger.Info("database lease renewed", "username", m.cur.Username, "ttl", s.TTL().String(), "capped", m.capped)
	return true
}

func (m *Manager) rotateWithRetry(ctx context.Context) error {
	backoff := time.Second
	for {
		err := m.rotate(ctx)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		m.setErr(err)
		m.Logger.Warn("database credential rotation failed", "error", err, "retry_in", backoff.String())
		if err := m.Sleep(ctx, backoff); err != nil {
			return err
		}
		backoff = min(backoff*2, 15*time.Second)
	}
}

func (m *Manager) rotate(ctx context.Context) error {
	c, err := m.fetch(ctx)
	if err != nil {
		return err
	}
	if err := m.OnRotate(ctx, c); err != nil {
		_ = m.API.RevokeLease(ctx, c.LeaseID)
		return fmt.Errorf("apply credential: %w", err)
	}
	m.mu.Lock()
	old := m.cur
	m.cur, m.increment, m.capped = c, c.TTL, false
	m.rotations++
	m.previous = old.Username
	m.lastErr = ""
	m.mu.Unlock()
	// The application has switched over, so the old credential is no longer
	// needed: revoke it now rather than waiting for it to expire.
	if err := m.API.RevokeLease(ctx, old.LeaseID); err != nil {
		m.Logger.Warn("revoking previous database lease failed; it will expire on its own", "error", err)
	}
	m.Logger.Info("database credential rotated", "username", c.Username, "previous", old.Username, "ttl", c.TTL.String())
	return nil
}

func (m *Manager) setErr(err error) {
	m.mu.Lock()
	m.lastErr = err.Error()
	m.mu.Unlock()
}

// Status returns a snapshot without secrets.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	ttl := 0
	if m.Now != nil {
		ttl = max(int(m.cur.ExpiresAt.Sub(m.Now()).Seconds()), 0)
	}
	return Status{
		Username:         m.cur.Username,
		IssuedAt:         m.cur.IssuedAt,
		ExpiresAt:        m.cur.ExpiresAt,
		LeaseTTLSeconds:  ttl,
		Renewals:         m.renewals,
		Rotations:        m.rotations,
		PreviousUsername: m.previous,
		LastError:        m.lastErr,
	}
}

// Ready reports whether a credential is held.
func (m *Manager) Ready() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cur.Username != ""
}
