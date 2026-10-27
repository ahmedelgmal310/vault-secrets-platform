package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRunScenarioAgainstFakeVault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/kubernetes/login":
			_, _ = w.Write([]byte(`{"auth":{"client_token":"t","lease_duration":60}}`))
		case "/v1/database/creds/orders-api":
			_, _ = w.Write([]byte(`{"lease_id":"x","data":{"username":"u"}}`))
		default:
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
		}
	}))
	defer srv.Close()

	var out bytes.Buffer
	code := run(context.Background(), []string{
		"-scenario", "legit", "-addr", srv.URL, "-role", "orders-api", "-expect-login", "allow",
		"-check", "read|database/creds/orders-api|allow",
		"-check", "read|kv/data/orders-api/config|deny",
	}, &out, func(string) ([]byte, error) { return []byte("jwt\n"), nil })
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
	sc := bufio.NewScanner(&out)
	lines := 0
	var last map[string]any
	for sc.Scan() {
		lines++
		last = map[string]any{}
		if err := json.Unmarshal(sc.Bytes(), &last); err != nil {
			t.Fatalf("line %d is not JSON: %s", lines, sc.Text())
		}
	}
	if lines != 4 || last["summary"] != true || last["failed"] != float64(0) {
		t.Fatalf("lines=%d last=%v", lines, last)
	}

	out.Reset()
	code = run(context.Background(), []string{"-addr", srv.URL, "-check", "read|database/creds/orders-api|deny"}, &out, nil)
	if code != 1 {
		t.Fatalf("an unexpected allow must exit 1, got %d", code)
	}
}

func TestRunUsageErrors(t *testing.T) {
	var out bytes.Buffer
	if code := run(context.Background(), []string{"-check", "bogus"}, &out, nil); code != 2 {
		t.Fatalf("bad check: %d", code)
	}
	if code := run(context.Background(), []string{"-nope"}, &out, nil); code != 2 {
		t.Fatalf("bad flag: %d", code)
	}
	readErr := func(string) ([]byte, error) { return nil, errors.New("missing") }
	if code := run(context.Background(), []string{"-expect-login", "deny"}, &out, readErr); code != 2 {
		t.Fatalf("missing token: %d", code)
	}
	var cl checkList
	_ = cl.Set("a")
	_ = cl.Set("b")
	if !strings.Contains(cl.String(), "a,b") {
		t.Fatal("checkList String")
	}
}
