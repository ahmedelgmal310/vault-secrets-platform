// Package certs issues short-lived TLS server certificates from the Vault PKI
// secrets engine and rotates them in memory before they expire. The private
// key is created by Vault for each certificate and never touches disk.
package certs

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/ahmedelgmal310/vault-secrets-platform/internal/vault"
)

// Issuer is the subset of the Vault client the rotator needs.
type Issuer interface {
	Write(ctx context.Context, path string, body map[string]any) (*vault.Secret, error)
}

// Status is a snapshot of the certificate currently served.
type Status struct {
	Serial    string    `json:"serial"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	Rotations int       `json:"rotations"`
	LastError string    `json:"last_error,omitempty"`
}

// Rotator holds the current certificate and replaces it at two thirds of its
// lifetime.
type Rotator struct {
	API        Issuer
	Path       string // e.g. pki_int/issue/orders-api
	CommonName string
	AltNames   []string
	TTL        time.Duration

	Logger *slog.Logger
	Now    func() time.Time
	Sleep  func(context.Context, time.Duration) error

	mu        sync.RWMutex
	cert      *tls.Certificate
	leaf      *x509.Certificate
	rotations int
	lastErr   string
}

func (r *Rotator) defaults() {
	if r.Now == nil {
		r.Now = time.Now
	}
	if r.Sleep == nil {
		r.Sleep = vault.SleepContext
	}
	if r.Logger == nil {
		r.Logger = slog.Default()
	}
}

// Issue requests a new certificate and makes it current.
func (r *Rotator) Issue(ctx context.Context) error {
	r.defaults()
	body := map[string]any{"common_name": r.CommonName, "ttl": fmt.Sprintf("%ds", int(r.TTL.Seconds()))}
	if len(r.AltNames) > 0 {
		body["alt_names"] = strings.Join(r.AltNames, ",")
	}
	s, err := r.API.Write(ctx, r.Path, body)
	if err != nil {
		return err
	}
	cert, leaf, err := Parse(s)
	if err != nil {
		return err
	}
	r.mu.Lock()
	first := r.cert == nil
	r.cert, r.leaf = cert, leaf
	if !first {
		r.rotations++
	}
	r.lastErr = ""
	r.mu.Unlock()
	r.Logger.Info("tls certificate issued", "serial", FormatSerial(leaf), "not_after", leaf.NotAfter.UTC().Format(time.RFC3339))
	return nil
}

// Run rotates the certificate until ctx is cancelled.
func (r *Rotator) Run(ctx context.Context) error {
	r.defaults()
	for {
		r.mu.RLock()
		nb, na := r.leaf.NotBefore, r.leaf.NotAfter
		r.mu.RUnlock()
		renewAt := nb.Add(na.Sub(nb) * 2 / 3)
		if err := r.Sleep(ctx, renewAt.Sub(r.Now())); err != nil {
			return err
		}
		backoff := time.Second
		for {
			err := r.Issue(ctx)
			if err == nil {
				break
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			r.mu.Lock()
			r.lastErr = err.Error()
			r.mu.Unlock()
			r.Logger.Warn("tls certificate rotation failed", "error", err, "retry_in", backoff.String())
			if err := r.Sleep(ctx, backoff); err != nil {
				return err
			}
			backoff = min(backoff*2, 15*time.Second)
		}
	}
}

// GetCertificate plugs into tls.Config so every handshake gets the current certificate.
func (r *Rotator) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.cert == nil {
		return nil, errors.New("no certificate issued yet")
	}
	return r.cert, nil
}

// Ready reports whether a certificate is held.
func (r *Rotator) Ready() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cert != nil
}

// Status returns a snapshot of the current certificate.
func (r *Rotator) Status() Status {
	r.mu.RLock()
	defer r.mu.RUnlock()
	st := Status{Rotations: r.rotations, LastError: r.lastErr}
	if r.leaf != nil {
		st.Serial = FormatSerial(r.leaf)
		st.NotBefore = r.leaf.NotBefore
		st.NotAfter = r.leaf.NotAfter
	}
	return st
}

// Parse builds a tls.Certificate (leaf plus CA chain) from a PKI issue response.
func Parse(s *vault.Secret) (*tls.Certificate, *x509.Certificate, error) {
	certPEM := s.StringField("certificate")
	keyPEM := s.StringField("private_key")
	if certPEM == "" || keyPEM == "" {
		return nil, nil, errors.New("pki response is missing certificate or private_key")
	}
	chain := strings.TrimSpace(certPEM) + "\n"
	if raw, ok := s.Data["ca_chain"].([]any); ok {
		for _, c := range raw {
			if p, ok := c.(string); ok && strings.TrimSpace(p) != strings.TrimSpace(certPEM) {
				chain += strings.TrimSpace(p) + "\n"
			}
		}
	} else if ca := s.StringField("issuing_ca"); ca != "" {
		chain += strings.TrimSpace(ca) + "\n"
	}
	cert, err := tls.X509KeyPair([]byte(chain), []byte(keyPEM))
	if err != nil {
		return nil, nil, fmt.Errorf("parse key pair: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, nil, fmt.Errorf("parse leaf: %w", err)
	}
	cert.Leaf = leaf
	return &cert, leaf, nil
}

// FormatSerial renders a serial the way Vault does (colon-separated hex).
func FormatSerial(c *x509.Certificate) string {
	b := c.SerialNumber.Bytes()
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("%02x", x)
	}
	return strings.Join(parts, ":")
}
