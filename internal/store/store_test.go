package store

import (
	"context"
	"testing"
	"time"
)

// The query paths need a real PostgreSQL and are exercised by the kind e2e
// job. These tests cover configuration and the not-connected behaviour.

func TestNewParsesDSNWithoutCredentials(t *testing.T) {
	s, err := New("host=postgres.db.svc port=5432 dbname=app sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	if s.base.ConnConfig.Host != "postgres.db.svc" || s.base.ConnConfig.Database != "app" || s.base.MaxConns != 4 {
		t.Fatalf("config %+v", s.base.ConnConfig)
	}
	if _, err := New("host=x port=notaport"); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestNotConnected(t *testing.T) {
	s, _ := New("host=127.0.0.1 port=1 dbname=app sslmode=disable connect_timeout=1")
	ctx := context.Background()
	if _, err := s.CurrentUser(ctx); err == nil {
		t.Fatal("expected error")
	}
	if _, err := s.InsertOrder(ctx, "a", "b"); err == nil {
		t.Fatal("expected error")
	}
	if _, err := s.GetOrder(ctx, 1); err == nil {
		t.Fatal("expected error")
	}
	s.Close()
}

func TestRotateFailsWhenDatabaseUnreachable(t *testing.T) {
	s, _ := New("host=127.0.0.1 port=1 dbname=app sslmode=disable connect_timeout=1")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Rotate(ctx, "u", "p"); err == nil {
		t.Fatal("expected ping error")
	}
	if _, err := s.CurrentUser(ctx); err == nil {
		t.Fatal("a failed rotation must not install a pool")
	}
}
