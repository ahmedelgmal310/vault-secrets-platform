// Package server is the HTTP API of orders-api.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/ahmedelgmal310/vault-secrets-platform/internal/store"
)

// DB is the data layer used by the handlers.
type DB interface {
	CurrentUser(ctx context.Context) (string, error)
	InsertOrder(ctx context.Context, item, noteCipher string) (int64, error)
	GetOrder(ctx context.Context, id int64) (store.Order, error)
}

// Crypter encrypts and decrypts with Vault transit.
type Crypter interface {
	Encrypt(ctx context.Context, plaintext []byte) (string, error)
	Decrypt(ctx context.Context, ciphertext string) ([]byte, error)
}

// Deps wires the handlers to the rest of the service.
type Deps struct {
	DB      DB
	Crypter Crypter
	// Ready reports whether a database credential and a TLS certificate are held.
	Ready func() bool
	// Status returns a JSON-serialisable snapshot without secrets.
	Status func() any
	Logger *slog.Logger
}

const maxBody = 64 << 10

// New returns the HTTP handler.
func New(d Deps) http.Handler {
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	h := &handlers{d: d}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", h.readyz)
	mux.HandleFunc("GET /status", h.status)
	mux.HandleFunc("GET /v1/db/whoami", h.whoami)
	mux.HandleFunc("POST /v1/orders", h.createOrder)
	mux.HandleFunc("GET /v1/orders/{id}", h.getOrder)
	return mux
}

type handlers struct{ d Deps }

func (h *handlers) readyz(w http.ResponseWriter, _ *http.Request) {
	if h.d.Ready != nil && !h.d.Ready() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not ready"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (h *handlers) status(w http.ResponseWriter, _ *http.Request) {
	if h.d.Status == nil {
		writeJSON(w, http.StatusOK, map[string]string{})
		return
	}
	writeJSON(w, http.StatusOK, h.d.Status())
}

func (h *handlers) whoami(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	u, err := h.d.DB.CurrentUser(ctx)
	if err != nil {
		h.fail(w, http.StatusServiceUnavailable, "database unavailable", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"current_user": u})
}

type orderRequest struct {
	Item string `json:"item"`
	Note string `json:"note"`
}

func (h *handlers) createOrder(w http.ResponseWriter, r *http.Request) {
	var req orderRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || req.Item == "" || len(req.Item) > 200 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body must be {\"item\": \"...\", \"note\": \"...\"}"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	ct, err := h.d.Crypter.Encrypt(ctx, []byte(req.Note))
	if err != nil {
		h.fail(w, http.StatusBadGateway, "encryption failed", err)
		return
	}
	id, err := h.d.DB.InsertOrder(ctx, req.Item, ct)
	if err != nil {
		h.fail(w, http.StatusServiceUnavailable, "database unavailable", err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "note_ciphertext": ct})
}

func (h *handlers) getOrder(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	o, err := h.d.DB.GetOrder(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if err != nil {
		h.fail(w, http.StatusServiceUnavailable, "database unavailable", err)
		return
	}
	pt, err := h.d.Crypter.Decrypt(ctx, o.NoteCipher)
	if err != nil {
		h.fail(w, http.StatusBadGateway, "decryption failed", err)
		return
	}
	o.NotePlaintext = string(pt)
	writeJSON(w, http.StatusOK, o)
}

func (h *handlers) fail(w http.ResponseWriter, code int, msg string, err error) {
	h.d.Logger.Error(msg, "error", err)
	writeJSON(w, code, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
