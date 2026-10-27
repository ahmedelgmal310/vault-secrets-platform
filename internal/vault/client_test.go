package vault

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type call struct {
	Method, Path, Token string
	Body                map[string]any
}

// fakeVault records calls and answers with handler-defined responses.
type fakeVault struct {
	t       *testing.T
	mu      sync.Mutex
	calls   []call
	respond func(c call) (int, any)
}

func (f *fakeVault) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	c := call{Method: r.Method, Path: strings.TrimPrefix(r.URL.Path, "/v1/"), Token: r.Header.Get("X-Vault-Token")}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &c.Body); err != nil {
			f.t.Errorf("bad json body: %v", err)
		}
	}
	f.mu.Lock()
	f.calls = append(f.calls, c)
	f.mu.Unlock()
	code, body := f.respond(c)
	w.WriteHeader(code)
	if s, ok := body.(string); ok {
		_, _ = io.WriteString(w, s)
		return
	}
	if body != nil {
		_ = json.NewEncoder(w).Encode(body)
	}
}

func (f *fakeVault) last() call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[len(f.calls)-1]
}

func newFake(t *testing.T, respond func(c call) (int, any)) (*fakeVault, *Client) {
	t.Helper()
	f := &fakeVault{t: t, respond: respond}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, New(srv.URL+"/", srv.Client())
}

func TestLoginKubernetesStoresToken(t *testing.T) {
	f, c := newFake(t, func(call) (int, any) {
		return 200, map[string]any{"auth": map[string]any{"client_token": "s.abc", "lease_duration": 900, "renewable": true, "token_policies": []string{"default", "orders-api"}}}
	})
	a, err := c.LoginKubernetes(context.Background(), "kubernetes", "orders-api", "jwt-value")
	if err != nil {
		t.Fatal(err)
	}
	if a.TTL() != 15*time.Minute || c.Token() != "s.abc" {
		t.Fatalf("auth = %+v token %q", a, c.Token())
	}
	got := f.last()
	if got.Method != http.MethodPost || got.Path != "auth/kubernetes/login" || got.Body["role"] != "orders-api" || got.Body["jwt"] != "jwt-value" {
		t.Fatalf("unexpected call %+v", got)
	}
	if got.Token != "" {
		t.Fatal("login must not send a token")
	}
}

func TestLoginWithoutAuthBlock(t *testing.T) {
	_, c := newFake(t, func(call) (int, any) { return 200, map[string]any{"data": map[string]any{}} })
	if _, err := c.LoginKubernetes(context.Background(), "kubernetes", "r", "j"); err == nil {
		t.Fatal("expected error")
	}
}

func TestErrorResponse(t *testing.T) {
	_, c := newFake(t, func(call) (int, any) {
		return 403, map[string]any{"errors": []string{"permission denied"}}
	})
	_, err := c.Read(context.Background(), "kv/data/x")
	var re *ResponseError
	if !errors.As(err, &re) || re.StatusCode != 403 || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("err = %v", err)
	}
	if StatusCode(err) != 403 || StatusCode(errors.New("x")) != 0 {
		t.Fatal("StatusCode mismatch")
	}
}

func TestErrorResponseWithoutBody(t *testing.T) {
	_, c := newFake(t, func(call) (int, any) { return 500, "" })
	_, err := c.Read(context.Background(), "x")
	if err == nil || !strings.Contains(err.Error(), "Internal Server Error") {
		t.Fatalf("err = %v", err)
	}
}

func TestReadWriteListRenewRevoke(t *testing.T) {
	f, c := newFake(t, func(cl call) (int, any) {
		if cl.Method == http.MethodPut && strings.HasPrefix(cl.Path, "sys/leases/revoke/") {
			return 204, nil
		}
		return 200, map[string]any{"lease_id": "database/creds/r/1", "lease_duration": 20, "data": map[string]any{"username": "u"}}
	})
	c.SetToken("tok")
	ctx := context.Background()

	s, err := c.Read(ctx, "/database/creds/r")
	if err != nil || s.StringField("username") != "u" || s.TTL() != 20*time.Second {
		t.Fatalf("read: %v %+v", err, s)
	}
	if got := f.last(); got.Method != http.MethodGet || got.Path != "database/creds/r" || got.Token != "tok" {
		t.Fatalf("read call %+v", got)
	}
	if _, err := c.Write(ctx, "transit/encrypt/k", map[string]any{"plaintext": "x"}); err != nil {
		t.Fatal(err)
	}
	if got := f.last(); got.Method != http.MethodPost || got.Body["plaintext"] != "x" {
		t.Fatalf("write call %+v", got)
	}
	if _, err := c.List(ctx, "database/roles"); err != nil {
		t.Fatal(err)
	}
	if got := f.last(); got.Method != "LIST" {
		t.Fatalf("list call %+v", got)
	}
	if _, err := c.RenewLease(ctx, "database/creds/r/1", 20*time.Second); err != nil {
		t.Fatal(err)
	}
	if got := f.last(); got.Path != "sys/leases/renew" || got.Body["lease_id"] != "database/creds/r/1" || got.Body["increment"] != float64(20) {
		t.Fatalf("renew call %+v", got)
	}
	if err := c.RevokeLease(ctx, "database/creds/r/1"); err != nil {
		t.Fatal(err)
	}
	if got := f.last(); got.Path != "sys/leases/revoke/database/creds/r/1" {
		t.Fatalf("revoke call %+v", got)
	}
	if err := c.RevokeLease(ctx, "../sys/seal"); err == nil {
		t.Fatal("expected invalid lease id error")
	}
	if err := c.RevokeLease(ctx, ""); err == nil {
		t.Fatal("expected invalid lease id error")
	}
}

func TestRenewSelf(t *testing.T) {
	f, c := newFake(t, func(call) (int, any) {
		return 200, map[string]any{"auth": map[string]any{"client_token": "t", "lease_duration": 600}}
	})
	c.SetToken("t")
	a, err := c.RenewSelf(context.Background(), 10*time.Minute)
	if err != nil || a.TTL() != 10*time.Minute {
		t.Fatalf("%v %+v", err, a)
	}
	if got := f.last(); got.Path != "auth/token/renew-self" || got.Body["increment"] != float64(600) {
		t.Fatalf("call %+v", got)
	}
}

func TestRenewSelfWithoutAuth(t *testing.T) {
	_, c := newFake(t, func(call) (int, any) { return 200, map[string]any{} })
	if _, err := c.RenewSelf(context.Background(), time.Minute); err == nil {
		t.Fatal("expected error")
	}
}

func TestDecodeErrorAndEmptyBody(t *testing.T) {
	_, c := newFake(t, func(cl call) (int, any) {
		if cl.Path == "bad" {
			return 200, "{not json"
		}
		return 204, nil
	})
	if _, err := c.Read(context.Background(), "bad"); err == nil {
		t.Fatal("expected decode error")
	}
	s, err := c.Read(context.Background(), "empty")
	if err != nil || s == nil {
		t.Fatalf("empty: %v", err)
	}
}

func TestTransportError(t *testing.T) {
	c := New("http://127.0.0.1:1", nil)
	if _, err := c.Read(context.Background(), "x"); err == nil {
		t.Fatal("expected error")
	}
	if _, err := c.Write(context.Background(), "x", map[string]any{"bad": func() {}}); err == nil {
		t.Fatal("expected encode error")
	}
	if _, err := New("http://bad host", nil).Read(context.Background(), "x"); err == nil {
		t.Fatal("expected request build error")
	}
}

func TestStringFieldNil(t *testing.T) {
	var s *Secret
	if s.StringField("x") != "" || (&Secret{Data: map[string]any{"n": 1}}).StringField("n") != "" {
		t.Fatal("expected empty")
	}
}

func TestTransitRoundTrip(t *testing.T) {
	_, c := newFake(t, func(cl call) (int, any) {
		switch cl.Path {
		case "transit/encrypt/orders":
			pt, _ := base64.StdEncoding.DecodeString(cl.Body["plaintext"].(string))
			return 200, map[string]any{"data": map[string]any{"ciphertext": "vault:v1:" + base64.StdEncoding.EncodeToString(pt)}}
		case "transit/decrypt/orders":
			ct := strings.TrimPrefix(cl.Body["ciphertext"].(string), "vault:v1:")
			return 200, map[string]any{"data": map[string]any{"plaintext": ct}}
		case "transit/encrypt/empty":
			return 200, map[string]any{"data": map[string]any{}}
		case "transit/decrypt/empty":
			return 200, map[string]any{"data": map[string]any{"plaintext": "%%%"}}
		}
		return 403, map[string]any{"errors": []string{"permission denied"}}
	})
	tr := &Transit{Client: c, Mount: "transit", Key: "orders"}
	ct, err := tr.Encrypt(context.Background(), []byte("hello"))
	if err != nil || !strings.HasPrefix(ct, "vault:v1:") {
		t.Fatalf("encrypt: %v %q", err, ct)
	}
	pt, err := tr.Decrypt(context.Background(), ct)
	if err != nil || string(pt) != "hello" {
		t.Fatalf("decrypt: %v %q", err, pt)
	}
	bad := &Transit{Client: c, Mount: "transit", Key: "empty"}
	if _, err := bad.Encrypt(context.Background(), []byte("x")); err == nil {
		t.Fatal("expected missing ciphertext error")
	}
	if _, err := bad.Decrypt(context.Background(), "x"); err == nil {
		t.Fatal("expected base64 error")
	}
	denied := &Transit{Client: c, Mount: "transit", Key: "other"}
	if _, err := denied.Encrypt(context.Background(), []byte("x")); StatusCode(err) != 403 {
		t.Fatalf("expected 403, got %v", err)
	}
	if _, err := denied.Decrypt(context.Background(), "x"); StatusCode(err) != 403 {
		t.Fatalf("expected 403, got %v", err)
	}
}
