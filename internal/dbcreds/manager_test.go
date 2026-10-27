package dbcreds

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ahmedelgmal310/vault-secrets-platform/internal/vault"
)

// fakeAPI simulates the database secrets engine with default_ttl/max_ttl.
type fakeAPI struct {
	mu         sync.Mutex
	now        *time.Time
	defaultTTL time.Duration
	maxTTL     time.Duration
	issued     map[string]time.Time
	revoked    []string
	seq        int
	readErrs   int // fail this many reads first
	renewErr   error
}

func (f *fakeAPI) Read(_ context.Context, path string) (*vault.Secret, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.readErrs > 0 {
		f.readErrs--
		return nil, &vault.ResponseError{StatusCode: 503, Errors: []string{"sealed"}}
	}
	f.seq++
	id := fmt.Sprintf("%s/%d", path, f.seq)
	f.issued[id] = *f.now
	return &vault.Secret{
		LeaseID:       id,
		LeaseDuration: int(f.defaultTTL.Seconds()),
		Data:          map[string]any{"username": fmt.Sprintf("v-orders-%d", f.seq), "password": "pw"},
	}, nil
}

func (f *fakeAPI) RenewLease(_ context.Context, id string, inc time.Duration) (*vault.Secret, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.renewErr != nil {
		return nil, f.renewErr
	}
	left := f.issued[id].Add(f.maxTTL).Sub(*f.now)
	ttl := min(inc, left)
	return &vault.Secret{LeaseID: id, LeaseDuration: int(ttl.Seconds())}, nil
}

func (f *fakeAPI) RevokeLease(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked = append(f.revoked, id)
	return nil
}

type harness struct {
	now     time.Time
	api     *fakeAPI
	m       *Manager
	applied []Credential
	cancel  context.CancelFunc
	ctx     context.Context
	sleeps  int
}

func newHarness(t *testing.T, maxSleeps int) *harness {
	t.Helper()
	h := &harness{now: time.Unix(1_000_000, 0)}
	h.api = &fakeAPI{now: &h.now, defaultTTL: 20 * time.Second, maxTTL: 60 * time.Second, issued: map[string]time.Time{}}
	h.ctx, h.cancel = context.WithCancel(context.Background())
	t.Cleanup(h.cancel)
	h.m = &Manager{
		API:  h.api,
		Path: "database/creds/orders-api",
		OnRotate: func(_ context.Context, c Credential) error {
			h.applied = append(h.applied, c)
			return nil
		},
		Now:    func() time.Time { return h.now },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Sleep: func(ctx context.Context, d time.Duration) error {
			h.sleeps++
			if h.sleeps > maxSleeps {
				h.cancel()
				return ctx.Err()
			}
			h.now = h.now.Add(d)
			return nil
		},
	}
	return h
}

func TestRenewsUntilMaxTTLThenRotatesAndRevokes(t *testing.T) {
	h := newHarness(t, 7)
	if err := h.m.Acquire(h.ctx); err != nil {
		t.Fatal(err)
	}
	if err := h.m.Run(h.ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("run: %v", err)
	}
	if len(h.applied) < 2 {
		t.Fatalf("expected a rotation, applied %d credentials", len(h.applied))
	}
	first, second := h.applied[0], h.applied[1]
	if first.Username == second.Username {
		t.Fatal("rotation must produce a new username")
	}
	// The first lease must have been used (renewed) but never beyond max_ttl.
	if !second.IssuedAt.Before(h.api.issued[first.LeaseID].Add(60 * time.Second)) {
		t.Fatalf("rotated at %v, after the first lease max_ttl", second.IssuedAt)
	}
	if len(h.api.revoked) == 0 || h.api.revoked[0] != first.LeaseID {
		t.Fatalf("old lease must be revoked after rotation, revoked=%v", h.api.revoked)
	}
	st := h.m.Status()
	if st.Renewals < 2 || st.Rotations < 1 || st.PreviousUsername != first.Username {
		t.Fatalf("status %+v", st)
	}
	if strings.Contains(fmt.Sprintf("%+v", st), "pw") {
		t.Fatal("status must never contain the password")
	}
	if !h.m.Ready() {
		t.Fatal("manager should be ready")
	}
}

func TestRenewalFailureRotatesImmediately(t *testing.T) {
	h := newHarness(t, 1)
	if err := h.m.Acquire(h.ctx); err != nil {
		t.Fatal(err)
	}
	h.api.renewErr = &vault.ResponseError{StatusCode: 400, Errors: []string{"lease not found"}}
	_ = h.m.Run(h.ctx)
	if len(h.applied) != 2 {
		t.Fatalf("applied %d credentials, want 2", len(h.applied))
	}
	if h.m.Status().Renewals != 0 {
		t.Fatal("no renewal should have succeeded")
	}
}

func TestRotationRetriesWithBackoff(t *testing.T) {
	h := newHarness(t, 3)
	if err := h.m.Acquire(h.ctx); err != nil {
		t.Fatal(err)
	}
	h.api.renewErr = errors.New("connection refused")
	h.api.readErrs = 2
	_ = h.m.Run(h.ctx)
	if len(h.applied) != 2 {
		t.Fatalf("applied %d credentials, want 2 after retries", len(h.applied))
	}
	if h.m.Status().LastError != "" {
		t.Fatal("last error should clear after a successful rotation")
	}
}

func TestAcquireErrors(t *testing.T) {
	h := newHarness(t, 0)
	h.api.readErrs = 1
	if err := h.m.Acquire(h.ctx); vault.StatusCode(err) != 503 {
		t.Fatalf("got %v", err)
	}
	if h.m.Ready() {
		t.Fatal("not ready without a credential")
	}

	h.m.OnRotate = func(context.Context, Credential) error { return errors.New("db down") }
	if err := h.m.Acquire(h.ctx); err == nil || !strings.Contains(err.Error(), "db down") {
		t.Fatalf("got %v", err)
	}
	if len(h.api.revoked) != 1 {
		t.Fatal("a credential the app could not use must be revoked")
	}
}

type incompleteAPI struct{}

func (incompleteAPI) RenewLease(context.Context, string, time.Duration) (*vault.Secret, error) {
	return nil, errors.New("unused")
}
func (incompleteAPI) RevokeLease(context.Context, string) error { return nil }
func (incompleteAPI) Read(context.Context, string) (*vault.Secret, error) {
	return &vault.Secret{LeaseID: "x", LeaseDuration: 20, Data: map[string]any{"username": "u"}}, nil
}

func TestIncompleteCredential(t *testing.T) {
	m := &Manager{API: incompleteAPI{}, OnRotate: func(context.Context, Credential) error { return nil }}
	if err := m.Acquire(context.Background()); err == nil {
		t.Fatal("expected error for missing password")
	}
}

func TestRotateApplyFailureRevokesNewLease(t *testing.T) {
	h := newHarness(t, 0)
	if err := h.m.Acquire(h.ctx); err != nil {
		t.Fatal(err)
	}
	h.m.OnRotate = func(context.Context, Credential) error { return errors.New("ping failed") }
	if err := h.m.rotate(h.ctx); err == nil {
		t.Fatal("expected error")
	}
	if len(h.api.revoked) != 1 || h.m.Status().Username != "v-orders-1" {
		t.Fatalf("revoked=%v status=%+v", h.api.revoked, h.m.Status())
	}
}

func TestRotateWithRetryStopsOnCancel(t *testing.T) {
	h := newHarness(t, 0)
	h.api.readErrs = 100
	h.cancel()
	if err := h.m.rotateWithRetry(h.ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}

func TestDefaults(t *testing.T) {
	m := &Manager{}
	m.defaults()
	if m.Now == nil || m.Sleep == nil || m.Logger == nil {
		t.Fatal("defaults not set")
	}
	if (&Manager{}).Status().LeaseTTLSeconds != 0 {
		t.Fatal("zero manager status")
	}
}
