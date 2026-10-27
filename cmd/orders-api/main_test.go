package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestLoadConfigDefaults(t *testing.T) {
	c, err := loadConfig(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.VaultAddr != "http://vault-active.vault.svc:8200" || c.Role != "orders-api" || c.CertTTL != 2*time.Minute || c.ListenAddr != ":8443" {
		t.Fatalf("%+v", c)
	}
}

func TestLoadConfigOverrides(t *testing.T) {
	c, err := loadConfig(env(map[string]string{
		"VAULT_ROLE":    "other",
		"TLS_ALT_NAMES": "a.svc, b.svc ,,",
		"TLS_CERT_TTL":  "5m",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Role != "other" || len(c.AltNames) != 2 || c.AltNames[1] != "b.svc" || c.CertTTL != 5*time.Minute {
		t.Fatalf("%+v", c)
	}
}

func TestLoadConfigRejects(t *testing.T) {
	for name, e := range map[string]map[string]string{
		"short ttl":      {"TLS_CERT_TTL": "5s"},
		"bad ttl":        {"TLS_CERT_TTL": "soon"},
		"static secrets": {"DB_DSN": "host=x password=hunter2"},
	} {
		if _, err := loadConfig(env(e)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestRetry(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	n := 0
	err := retry(context.Background(), logger, "op", func(context.Context) error {
		n++
		if n < 2 {
			return errors.New("not yet")
		}
		return nil
	})
	if err != nil || n != 2 {
		t.Fatalf("err=%v n=%d", err, n)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := retry(ctx, logger, "op", func(context.Context) error { return errors.New("x") }); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}
