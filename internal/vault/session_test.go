package vault

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// stepSleep returns a Sleep func that succeeds n times and then cancels.
func stepSleep(cancel context.CancelFunc, n int, got *[]time.Duration) func(context.Context, time.Duration) error {
	var calls int32
	return func(ctx context.Context, d time.Duration) error {
		*got = append(*got, d)
		if int(atomic.AddInt32(&calls, 1)) > n {
			cancel()
			return ctx.Err()
		}
		return nil
	}
}

func TestRenewAfter(t *testing.T) {
	now := time.Unix(1000, 0)
	if got := RenewAfter(now, now.Add(30*time.Second)); got != 20*time.Second {
		t.Fatalf("got %v", got)
	}
	if got := RenewAfter(now, now.Add(-time.Second)); got != 0 {
		t.Fatalf("got %v", got)
	}
}

func TestSleepContext(t *testing.T) {
	if err := SleepContext(context.Background(), time.Millisecond); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := SleepContext(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	if err := SleepContext(ctx, 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}

func TestSessionLoginRenewAndRelogin(t *testing.T) {
	var renewTTL atomic.Int64
	renewTTL.Store(900)
	var logins atomic.Int32
	_, c := newFake(t, func(cl call) (int, any) {
		switch cl.Path {
		case "auth/kubernetes/login":
			logins.Add(1)
			return 200, map[string]any{"auth": map[string]any{"client_token": "t", "lease_duration": 900, "token_policies": []string{"orders-api"}}}
		case "auth/token/renew-self":
			ttl := renewTTL.Load()
			renewTTL.Store(10) // second renewal is capped below MinTTL
			return 200, map[string]any{"auth": map[string]any{"client_token": "t", "lease_duration": ttl}}
		}
		return 404, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var sleeps []time.Duration
	s := &Session{
		Client: c, Mount: "kubernetes", Role: "orders-api", JWTPath: "/token",
		ReadFile: func(string) ([]byte, error) { return []byte("jwt\n"), nil },
		Sleep:    stepSleep(cancel, 2, &sleeps),
	}
	if err := s.Login(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("run: %v", err)
	}
	st := s.Status()
	if st.Logins != 2 || st.Renewals != 1 || st.Role != "orders-api" || len(st.Policies) != 1 {
		t.Fatalf("status %+v", st)
	}
	if logins.Load() != 2 {
		t.Fatalf("logins = %d", logins.Load())
	}
	if sleeps[0] < 9*time.Minute || sleeps[0] > 10*time.Minute {
		t.Fatalf("first renewal should wait ~2/3 of 15m, got %v", sleeps[0])
	}
}

func TestSessionRenewErrorRetriesLogin(t *testing.T) {
	var loginAttempts atomic.Int32
	_, c := newFake(t, func(cl call) (int, any) {
		switch cl.Path {
		case "auth/kubernetes/login":
			if loginAttempts.Add(1) == 2 {
				return 503, map[string]any{"errors": []string{"sealed"}}
			}
			return 200, map[string]any{"auth": map[string]any{"client_token": "t", "lease_duration": 60}}
		case "auth/token/renew-self":
			return 403, map[string]any{"errors": []string{"permission denied"}}
		}
		return 404, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var sleeps []time.Duration
	s := &Session{
		Client: c, Mount: "kubernetes", Role: "r", JWTPath: "/token",
		ReadFile: func(string) ([]byte, error) { return []byte("jwt"), nil },
		Sleep:    stepSleep(cancel, 2, &sleeps),
	}
	if err := s.Login(ctx); err != nil {
		t.Fatal(err)
	}
	_ = s.Run(ctx)
	if loginAttempts.Load() != 3 {
		t.Fatalf("login attempts = %d, want 3 (initial, failed retry, success)", loginAttempts.Load())
	}
	if sleeps[1] != time.Second {
		t.Fatalf("retry backoff = %v", sleeps[1])
	}
}

func TestSessionLoginReadError(t *testing.T) {
	s := &Session{Client: New("http://127.0.0.1:1", nil), ReadFile: func(string) ([]byte, error) { return nil, errors.New("no file") }}
	if err := s.Login(context.Background()); err == nil {
		t.Fatal("expected error")
	}
}

func TestLoginWithRetryStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := &Session{Client: New("http://127.0.0.1:1", nil), ReadFile: func(string) ([]byte, error) { return []byte("j"), nil }}
	s.defaults()
	if err := s.loginWithRetry(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}
