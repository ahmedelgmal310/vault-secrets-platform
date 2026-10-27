package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ahmedelgmal310/vault-secrets-platform/internal/vault"
)

// fakePKI signs leaf certificates with an in-memory CA, like pki_int/issue.
type fakePKI struct {
	t       *testing.T
	ca      *x509.Certificate
	caKey   *ecdsa.PrivateKey
	caPEM   string
	now     func() time.Time
	serial  int64
	fail    int
	bodies  []map[string]any
	noChain bool
}

func newFakePKI(t *testing.T, now func() time.Time) *fakePKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test intermediate"},
		NotBefore:             now().Add(-time.Hour),
		NotAfter:              now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	return &fakePKI{t: t, ca: ca, caKey: key, now: now, serial: 100,
		caPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

func (f *fakePKI) Write(_ context.Context, _ string, body map[string]any) (*vault.Secret, error) {
	f.bodies = append(f.bodies, body)
	if f.fail > 0 {
		f.fail--
		return nil, &vault.ResponseError{StatusCode: 503, Errors: []string{"sealed"}}
	}
	ttl, err := time.ParseDuration(body["ttl"].(string))
	if err != nil {
		f.t.Fatalf("ttl: %v", err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f.serial++
	tmpl := &x509.Certificate{
		SerialNumber: new(big.Int).Lsh(big.NewInt(f.serial), 64),
		Subject:      pkix.Name{CommonName: body["common_name"].(string)},
		DNSNames:     []string{body["common_name"].(string)},
		NotBefore:    f.now().Add(-30 * time.Second),
		NotAfter:     f.now().Add(ttl),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, f.ca, &key.PublicKey, f.caKey)
	if err != nil {
		f.t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	data := map[string]any{
		"certificate": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		"private_key": string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})),
		"issuing_ca":  f.caPEM,
	}
	if !f.noChain {
		data["ca_chain"] = []any{f.caPEM}
	}
	return &vault.Secret{Data: data}, nil
}

func TestIssueRotateAndServe(t *testing.T) {
	now := time.Unix(2_000_000, 0)
	clock := func() time.Time { return now }
	pki := newFakePKI(t, clock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var waits []time.Duration
	r := &Rotator{
		API: pki, Path: "pki_int/issue/orders-api", CommonName: "orders-api.orders.svc",
		AltNames: []string{"orders-api.orders.svc.cluster.local"}, TTL: 2 * time.Minute,
		Now:    clock,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Sleep: func(ctx context.Context, d time.Duration) error {
			waits = append(waits, d)
			if len(waits) > 2 {
				cancel()
				return ctx.Err()
			}
			now = now.Add(d)
			return nil
		},
	}
	if _, err := r.GetCertificate(nil); err == nil || r.Ready() {
		t.Fatal("no certificate before Issue")
	}
	if err := r.Issue(ctx); err != nil {
		t.Fatal(err)
	}
	first := r.Status()
	c, err := r.GetCertificate(nil)
	if err != nil || len(c.Certificate) != 2 {
		t.Fatalf("want leaf + CA in chain, got %v %d", err, len(c.Certificate))
	}
	if pki.bodies[0]["ttl"] != "120s" || pki.bodies[0]["alt_names"] != "orders-api.orders.svc.cluster.local" {
		t.Fatalf("issue body %+v", pki.bodies[0])
	}
	if err := r.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("run: %v", err)
	}
	// Lifetime is 150s (30s backdate + 120s TTL); rotate at 2/3 = 100s after
	// NotBefore, i.e. 70s after issue.
	if waits[0] != 70*time.Second {
		t.Fatalf("first rotation wait = %v, want 70s", waits[0])
	}
	st := r.Status()
	if st.Rotations != 2 || st.Serial == first.Serial || !st.NotAfter.After(first.NotAfter) {
		t.Fatalf("status %+v first %+v", st, first)
	}
	if !strings.Contains(st.Serial, ":") {
		t.Fatalf("serial format %q", st.Serial)
	}
}

func TestRunRetriesFailedIssue(t *testing.T) {
	now := time.Unix(2_000_000, 0)
	clock := func() time.Time { return now }
	pki := newFakePKI(t, clock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var waits []time.Duration
	r := &Rotator{API: pki, Path: "p", CommonName: "a.b", TTL: time.Minute, Now: clock,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Sleep: func(ctx context.Context, d time.Duration) error {
			waits = append(waits, d)
			if len(waits) > 3 {
				cancel()
				return ctx.Err()
			}
			now = now.Add(d)
			return nil
		}}
	if err := r.Issue(ctx); err != nil {
		t.Fatal(err)
	}
	pki.fail = 2
	_ = r.Run(ctx)
	if waits[1] != time.Second || waits[2] != 2*time.Second {
		t.Fatalf("backoff waits %v", waits)
	}
	if r.Status().Rotations != 1 || r.Status().LastError != "" {
		t.Fatalf("status %+v", r.Status())
	}
}

func TestIssueError(t *testing.T) {
	pki := newFakePKI(t, time.Now)
	pki.fail = 1
	r := &Rotator{API: pki, Path: "p", CommonName: "a.b", TTL: time.Minute}
	if err := r.Issue(context.Background()); vault.StatusCode(err) != 503 {
		t.Fatalf("got %v", err)
	}
}

func TestParse(t *testing.T) {
	pki := newFakePKI(t, time.Now)
	pki.noChain = true
	s, _ := pki.Write(context.Background(), "p", map[string]any{"common_name": "a.b", "ttl": "60s"})
	c, leaf, err := Parse(s)
	if err != nil || len(c.Certificate) != 2 || leaf.Subject.CommonName != "a.b" {
		t.Fatalf("issuing_ca fallback: %v", err)
	}
	if _, _, err := Parse(&vault.Secret{Data: map[string]any{}}); err == nil {
		t.Fatal("expected missing fields error")
	}
	bad := &vault.Secret{Data: map[string]any{"certificate": "x", "private_key": "y"}}
	if _, _, err := Parse(bad); err == nil {
		t.Fatal("expected parse error")
	}
}
