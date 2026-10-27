package vault

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"
)

// Session keeps a Kubernetes-auth Vault token alive: it logs in with the pod's
// projected service account token, renews the Vault token at two thirds of its
// TTL and logs in again when renewal fails or is capped by token_max_ttl.
type Session struct {
	Client  *Client
	Mount   string
	Role    string
	JWTPath string

	// MinTTL: when a renewal grants less than this, log in again instead.
	MinTTL time.Duration

	Logger   *slog.Logger
	ReadFile func(string) ([]byte, error)
	Sleep    func(context.Context, time.Duration) error
	Now      func() time.Time

	mu       sync.Mutex
	ttl      time.Duration
	expires  time.Time
	logins   int
	renewals int
	policies []string
}

// SessionStatus is a point-in-time view of the session, safe to expose.
type SessionStatus struct {
	Role      string    `json:"role"`
	Policies  []string  `json:"policies"`
	ExpiresAt time.Time `json:"expires_at"`
	Logins    int       `json:"logins"`
	Renewals  int       `json:"renewals"`
}

func (s *Session) defaults() {
	if s.ReadFile == nil {
		s.ReadFile = os.ReadFile
	}
	if s.Sleep == nil {
		s.Sleep = SleepContext
	}
	if s.Now == nil {
		s.Now = time.Now
	}
	if s.Logger == nil {
		s.Logger = slog.Default()
	}
	if s.MinTTL == 0 {
		s.MinTTL = 30 * time.Second
	}
}

// Login reads the service account token from JWTPath and logs in.
func (s *Session) Login(ctx context.Context) error {
	s.defaults()
	jwt, err := s.ReadFile(s.JWTPath)
	if err != nil {
		return fmt.Errorf("read service account token: %w", err)
	}
	a, err := s.Client.LoginKubernetes(ctx, s.Mount, s.Role, strings.TrimSpace(string(jwt)))
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.ttl = a.TTL()
	s.expires = s.Now().Add(a.TTL())
	s.logins++
	s.policies = a.TokenPolicies
	s.mu.Unlock()
	s.Logger.Info("vault login", "role", s.Role, "policies", a.TokenPolicies, "ttl", a.TTL().String())
	return nil
}

// Run renews the token until ctx is cancelled.
func (s *Session) Run(ctx context.Context) error {
	s.defaults()
	for {
		s.mu.Lock()
		wait := RenewAfter(s.Now(), s.expires)
		ttl := s.ttl
		s.mu.Unlock()
		if err := s.Sleep(ctx, wait); err != nil {
			return err
		}
		a, err := s.Client.RenewSelf(ctx, ttl)
		if err == nil && a.TTL() >= s.MinTTL {
			s.mu.Lock()
			s.expires = s.Now().Add(a.TTL())
			s.renewals++
			s.mu.Unlock()
			s.Logger.Info("vault token renewed", "ttl", a.TTL().String())
			continue
		}
		if err != nil {
			s.Logger.Warn("vault token renewal failed, logging in again", "error", err)
		} else {
			s.Logger.Info("vault token near max TTL, logging in again", "ttl", a.TTL().String())
		}
		if err := s.loginWithRetry(ctx); err != nil {
			return err
		}
	}
}

func (s *Session) loginWithRetry(ctx context.Context) error {
	backoff := time.Second
	for {
		err := s.Login(ctx)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.Logger.Warn("vault login failed", "error", err, "retry_in", backoff.String())
		if err := s.Sleep(ctx, backoff); err != nil {
			return err
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

// Status returns a snapshot of the session.
func (s *Session) Status() SessionStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return SessionStatus{Role: s.Role, Policies: append([]string(nil), s.policies...), ExpiresAt: s.expires, Logins: s.logins, Renewals: s.renewals}
}

// RenewAfter returns how long to wait before renewing something that expires
// at expires: two thirds of the remaining lifetime, never negative.
func RenewAfter(now, expires time.Time) time.Duration {
	remaining := expires.Sub(now)
	if remaining <= 0 {
		return 0
	}
	return remaining * 2 / 3
}

// SleepContext sleeps for d or until ctx is done.
func SleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
