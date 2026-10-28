// Command orders-api is a small service that holds no static secrets. At
// start-up it authenticates to Vault with its Kubernetes service account,
// then keeps three things fresh for as long as it runs:
//
//   - its Vault token (renewed, or re-login when capped),
//   - a dynamic PostgreSQL credential (renewed, rotated at max_ttl),
//   - a short-lived TLS server certificate from Vault PKI (rotated at 2/3 lifetime).
//
// Order notes are encrypted with Vault transit before they reach the database.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ahmedelgmal310/vault-secrets-platform/internal/certs"
	"github.com/ahmedelgmal310/vault-secrets-platform/internal/dbcreds"
	"github.com/ahmedelgmal310/vault-secrets-platform/internal/server"
	"github.com/ahmedelgmal310/vault-secrets-platform/internal/store"
	"github.com/ahmedelgmal310/vault-secrets-platform/internal/vault"
)

var version = "dev"

type config struct {
	VaultAddr    string
	AuthMount    string
	Role         string
	JWTPath      string
	DBCredsPath  string
	DBDSN        string
	PKIPath      string
	CommonName   string
	AltNames     []string
	CertTTL      time.Duration
	TransitMount string
	TransitKey   string
	ListenAddr   string
}

func loadConfig(getenv func(string) string) (config, error) {
	get := func(k, def string) string {
		if v := strings.TrimSpace(getenv(k)); v != "" {
			return v
		}
		return def
	}
	c := config{
		VaultAddr:    get("VAULT_ADDR", "http://vault-active.vault.svc:8200"),
		AuthMount:    get("VAULT_AUTH_MOUNT", "kubernetes"),
		Role:         get("VAULT_ROLE", "orders-api"),
		JWTPath:      get("VAULT_JWT_PATH", "/var/run/secrets/vault/token"),
		DBCredsPath:  get("DB_CREDS_PATH", "database/creds/orders-api"),
		DBDSN:        get("DB_DSN", "host=postgres.db.svc port=5432 dbname=app sslmode=disable"),
		PKIPath:      get("PKI_ISSUE_PATH", "pki_int/issue/orders-api"),
		CommonName:   get("TLS_COMMON_NAME", "orders-api.orders.svc"),
		TransitMount: get("TRANSIT_MOUNT", "transit"),
		TransitKey:   get("TRANSIT_KEY", "orders"),
		ListenAddr:   get("LISTEN_ADDR", ":8443"),
	}
	if alt := get("TLS_ALT_NAMES", ""); alt != "" {
		for _, a := range strings.Split(alt, ",") {
			if a = strings.TrimSpace(a); a != "" {
				c.AltNames = append(c.AltNames, a)
			}
		}
	}
	ttl, err := time.ParseDuration(get("TLS_CERT_TTL", "2m"))
	if err != nil || ttl < 30*time.Second {
		return config{}, fmt.Errorf("TLS_CERT_TTL must be a duration of at least 30s")
	}
	c.CertTTL = ttl
	if strings.Contains(strings.ToLower(c.DBDSN), "password") {
		return config{}, errors.New("DB_DSN must not contain credentials; they come from Vault")
	}
	return c, nil
}

func main() { os.Exit(realMain()) }

func realMain() int {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("service", "orders-api", "version", version)
	slog.SetDefault(logger)
	cfg, err := loadConfig(os.Getenv)
	if err != nil {
		logger.Error("invalid configuration", "error", err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg, logger); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("exiting", "error", err)
		return 1
	}
	return 0
}

// retry runs fn until it succeeds or ctx ends, with capped exponential backoff.
func retry(ctx context.Context, logger *slog.Logger, what string, fn func(context.Context) error) error {
	backoff := time.Second
	for {
		err := fn(ctx)
		if err == nil {
			return nil
		}
		logger.Warn(what+" failed", "error", err, "retry_in", backoff.String())
		if err := vault.SleepContext(ctx, backoff); err != nil {
			return err
		}
		backoff = min(backoff*2, 15*time.Second)
	}
}

func run(ctx context.Context, cfg config, logger *slog.Logger) error {
	vc := vault.New(cfg.VaultAddr, nil)
	sess := &vault.Session{Client: vc, Mount: cfg.AuthMount, Role: cfg.Role, JWTPath: cfg.JWTPath, Logger: logger}
	if err := retry(ctx, logger, "vault login", sess.Login); err != nil {
		return err
	}

	rot := &certs.Rotator{API: vc, Path: cfg.PKIPath, CommonName: cfg.CommonName, AltNames: cfg.AltNames, TTL: cfg.CertTTL, Logger: logger}
	if err := retry(ctx, logger, "tls certificate issue", rot.Issue); err != nil {
		return err
	}

	db, err := store.New(cfg.DBDSN)
	if err != nil {
		return err
	}
	defer db.Close()
	creds := &dbcreds.Manager{
		API:  vc,
		Path: cfg.DBCredsPath,
		OnRotate: func(ctx context.Context, c dbcreds.Credential) error {
			return db.Rotate(ctx, c.Username, c.Password)
		},
		Logger: logger,
	}
	if err := retry(ctx, logger, "database credential", creds.Acquire); err != nil {
		return err
	}

	errc := make(chan error, 4)
	go func() { errc <- fmt.Errorf("vault session: %w", sess.Run(ctx)) }()
	go func() { errc <- fmt.Errorf("db credentials: %w", creds.Run(ctx)) }()
	go func() { errc <- fmt.Errorf("tls rotation: %w", rot.Run(ctx)) }()

	handler := server.New(server.Deps{
		DB:      db,
		Crypter: &vault.Transit{Client: vc, Mount: cfg.TransitMount, Key: cfg.TransitKey},
		Ready:   func() bool { return creds.Ready() && rot.Ready() },
		Status: func() any {
			return map[string]any{
				"version":  version,
				"vault":    sess.Status(),
				"database": creds.Status(),
				"tls":      rot.Status(),
			}
		},
		Logger: logger,
	})
	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: rot.GetCertificate,
		},
	}
	go func() {
		logger.Info("listening", "addr", cfg.ListenAddr)
		if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- fmt.Errorf("http server: %w", err)
		}
	}()

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errc:
	}
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Warn("shutdown", "error", err)
	}
	return runErr
}
