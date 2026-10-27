package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ahmedelgmal310/vault-secrets-platform/internal/store"
)

type fakeDB struct {
	user   string
	err    error
	orders map[int64]store.Order
}

func (f *fakeDB) CurrentUser(context.Context) (string, error) { return f.user, f.err }

func (f *fakeDB) InsertOrder(_ context.Context, item, ct string) (int64, error) {
	if f.err != nil {
		return 0, f.err
	}
	id := int64(len(f.orders) + 1)
	f.orders[id] = store.Order{ID: id, Item: item, NoteCipher: ct, CreatedBy: f.user}
	return id, nil
}

func (f *fakeDB) GetOrder(_ context.Context, id int64) (store.Order, error) {
	if f.err != nil {
		return store.Order{}, f.err
	}
	o, ok := f.orders[id]
	if !ok {
		return store.Order{}, store.ErrNotFound
	}
	return o, nil
}

type fakeCrypter struct{ err error }

func (f fakeCrypter) Encrypt(_ context.Context, p []byte) (string, error) {
	return "vault:v1:" + strings.ToUpper(string(p)), f.err
}

func (f fakeCrypter) Decrypt(_ context.Context, c string) ([]byte, error) {
	return []byte(strings.ToLower(strings.TrimPrefix(c, "vault:v1:"))), f.err
}

func newTestServer(db *fakeDB, cr Crypter, ready bool) http.Handler {
	return New(Deps{
		DB: db, Crypter: cr,
		Ready:  func() bool { return ready },
		Status: func() any { return map[string]string{"database": "v-orders-1"} },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
}

func do(t *testing.T, h http.Handler, method, path, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("%s %s: missing Cache-Control: no-store", method, path)
	}
	return rec.Code, out
}

func TestHealthReadyStatus(t *testing.T) {
	db := &fakeDB{user: "v-orders-1", orders: map[int64]store.Order{}}
	h := newTestServer(db, fakeCrypter{}, true)
	if code, _ := do(t, h, "GET", "/healthz", ""); code != 200 {
		t.Fatalf("healthz %d", code)
	}
	if code, _ := do(t, h, "GET", "/readyz", ""); code != 200 {
		t.Fatalf("readyz %d", code)
	}
	if code, body := do(t, h, "GET", "/status", ""); code != 200 || body["database"] != "v-orders-1" {
		t.Fatalf("status %d %v", code, body)
	}
	notReady := newTestServer(db, fakeCrypter{}, false)
	if code, _ := do(t, notReady, "GET", "/readyz", ""); code != 503 {
		t.Fatalf("readyz not ready %d", code)
	}
	bare := New(Deps{DB: db, Crypter: fakeCrypter{}})
	if code, _ := do(t, bare, "GET", "/status", ""); code != 200 {
		t.Fatalf("status without func %d", code)
	}
}

func TestWhoami(t *testing.T) {
	db := &fakeDB{user: "v-kubernetes-orders-api-abc", orders: map[int64]store.Order{}}
	h := newTestServer(db, fakeCrypter{}, true)
	code, body := do(t, h, "GET", "/v1/db/whoami", "")
	if code != 200 || body["current_user"] != db.user {
		t.Fatalf("%d %v", code, body)
	}
	db.err = errors.New("password authentication failed")
	code, body = do(t, h, "GET", "/v1/db/whoami", "")
	if code != 503 || strings.Contains(body["error"].(string), "password") {
		t.Fatalf("errors must not leak details: %d %v", code, body)
	}
}

func TestCreateAndGetOrder(t *testing.T) {
	db := &fakeDB{user: "u", orders: map[int64]store.Order{}}
	h := newTestServer(db, fakeCrypter{}, true)
	code, body := do(t, h, "POST", "/v1/orders", `{"item":"book","note":"leave at door"}`)
	if code != 201 || body["note_ciphertext"] != "vault:v1:LEAVE AT DOOR" {
		t.Fatalf("create %d %v", code, body)
	}
	if db.orders[1].NoteCipher != "vault:v1:LEAVE AT DOOR" {
		t.Fatal("database must store ciphertext only")
	}
	code, body = do(t, h, "GET", "/v1/orders/1", "")
	if code != 200 || body["note"] != "leave at door" || body["note_ciphertext"] != "vault:v1:LEAVE AT DOOR" {
		t.Fatalf("get %d %v", code, body)
	}
	if code, _ := do(t, h, "GET", "/v1/orders/99", ""); code != 404 {
		t.Fatalf("missing order %d", code)
	}
	if code, _ := do(t, h, "GET", "/v1/orders/abc", ""); code != 400 {
		t.Fatalf("bad id %d", code)
	}
}

func TestCreateOrderValidation(t *testing.T) {
	h := newTestServer(&fakeDB{orders: map[int64]store.Order{}}, fakeCrypter{}, true)
	for _, body := range []string{``, `{}`, `{"item":""}`, `{"item":"x","extra":1}`, `{"item":"` + strings.Repeat("a", 201) + `"}`} {
		if code, _ := do(t, h, "POST", "/v1/orders", body); code != 400 {
			t.Errorf("body %.30q: got %d, want 400", body, code)
		}
	}
}

func TestDependencyFailures(t *testing.T) {
	db := &fakeDB{orders: map[int64]store.Order{1: {ID: 1, NoteCipher: "vault:v1:X"}}}
	h := newTestServer(db, fakeCrypter{err: errors.New("403")}, true)
	if code, _ := do(t, h, "POST", "/v1/orders", `{"item":"a","note":"b"}`); code != 502 {
		t.Fatalf("encrypt failure %d", code)
	}
	if code, _ := do(t, h, "GET", "/v1/orders/1", ""); code != 502 {
		t.Fatalf("decrypt failure %d", code)
	}
	db.err = errors.New("down")
	h = newTestServer(db, fakeCrypter{}, true)
	if code, _ := do(t, h, "POST", "/v1/orders", `{"item":"a","note":"b"}`); code != 503 {
		t.Fatalf("insert failure %d", code)
	}
	if code, _ := do(t, h, "GET", "/v1/orders/1", ""); code != 503 {
		t.Fatalf("get failure %d", code)
	}
}
