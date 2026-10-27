// Package store is the PostgreSQL data layer. Its connection pool is replaced
// atomically whenever Vault hands out a new dynamic credential.
package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Order is a row of the orders table. Note holds Vault transit ciphertext.
type Order struct {
	ID            int64     `json:"id"`
	Item          string    `json:"item"`
	NoteCipher    string    `json:"note_ciphertext"`
	CreatedBy     string    `json:"created_by"`
	CreatedAt     time.Time `json:"created_at"`
	NotePlaintext string    `json:"note,omitempty"`
}

// ErrNotFound is returned when an order does not exist.
var ErrNotFound = errors.New("not found")

// Store wraps a swappable pgx pool.
type Store struct {
	base *pgxpool.Config

	mu   sync.RWMutex
	pool *pgxpool.Pool
}

// New parses a connection string without credentials, for example
// "host=postgres.db.svc port=5432 dbname=app sslmode=disable".
func New(dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}
	cfg.MaxConns = 4
	cfg.MaxConnIdleTime = 30 * time.Second
	return &Store{base: cfg}, nil
}

// Rotate opens a pool with the new credential, checks it, swaps it in and
// closes the old pool once its in-flight queries finish.
func (s *Store) Rotate(ctx context.Context, user, password string) error {
	cfg := s.base.Copy()
	cfg.ConnConfig.User = user
	cfg.ConnConfig.Password = password
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return fmt.Errorf("open pool: %w", err)
	}
	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(pctx); err != nil {
		pool.Close()
		return fmt.Errorf("ping with new credential: %w", err)
	}
	s.mu.Lock()
	old := s.pool
	s.pool = pool
	s.mu.Unlock()
	if old != nil {
		old.Close()
	}
	return nil
}

func (s *Store) get() (*pgxpool.Pool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.pool == nil {
		return nil, errors.New("database not connected")
	}
	return s.pool, nil
}

// CurrentUser returns the database role the pool is connected as.
func (s *Store) CurrentUser(ctx context.Context) (string, error) {
	p, err := s.get()
	if err != nil {
		return "", err
	}
	var u string
	err = p.QueryRow(ctx, "SELECT current_user").Scan(&u)
	return u, err
}

// InsertOrder stores an order and returns its id.
func (s *Store) InsertOrder(ctx context.Context, item, noteCipher string) (int64, error) {
	p, err := s.get()
	if err != nil {
		return 0, err
	}
	var id int64
	err = p.QueryRow(ctx, "INSERT INTO orders (item, note_ciphertext) VALUES ($1, $2) RETURNING id", item, noteCipher).Scan(&id)
	return id, err
}

// GetOrder loads one order.
func (s *Store) GetOrder(ctx context.Context, id int64) (Order, error) {
	p, err := s.get()
	if err != nil {
		return Order{}, err
	}
	var o Order
	err = p.QueryRow(ctx, "SELECT id, item, note_ciphertext, created_by, created_at FROM orders WHERE id = $1", id).
		Scan(&o.ID, &o.Item, &o.NoteCipher, &o.CreatedBy, &o.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Order{}, ErrNotFound
	}
	return o, err
}

// Close closes the current pool.
func (s *Store) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pool != nil {
		s.pool.Close()
		s.pool = nil
	}
}
