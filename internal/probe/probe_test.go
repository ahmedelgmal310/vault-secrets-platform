package probe

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/ahmedelgmal310/vault-secrets-platform/internal/vault"
)

func TestParseCheck(t *testing.T) {
	c, err := ParseCheck(`write|pki_int/issue/orders-api|deny|{"common_name":"evil.example.com"}`)
	if err != nil || c.Op != "write" || c.Body["common_name"] != "evil.example.com" || c.Expect != Deny {
		t.Fatalf("%v %+v", err, c)
	}
	if c.String() != "write pki_int/issue/orders-api" {
		t.Fatalf("string %q", c.String())
	}
	c, err = ParseCheck("tcp|postgres.db.svc:5432|deny")
	if err != nil || c.Target != "postgres.db.svc:5432" {
		t.Fatalf("%v %+v", err, c)
	}
	for _, bad := range []string{"read|x", "delete|x|deny", "read|x|maybe", "read||deny", "write|x|deny|{bad"} {
		if _, err := ParseCheck(bad); err == nil {
			t.Errorf("%q: expected error", bad)
		}
	}
}

type fakeVault struct {
	loginErr error
	allowed  map[string]bool
}

func (f *fakeVault) LoginKubernetes(context.Context, string, string, string) (*vault.Auth, error) {
	if f.loginErr != nil {
		return nil, f.loginErr
	}
	return &vault.Auth{ClientToken: "t"}, nil
}

func (f *fakeVault) answer(op, path string) (*vault.Secret, error) {
	if f.allowed[op+" "+path] {
		return &vault.Secret{}, nil
	}
	return nil, &vault.ResponseError{StatusCode: 403, Errors: []string{"permission denied"}}
}

func (f *fakeVault) Read(_ context.Context, p string) (*vault.Secret, error) {
	return f.answer("read", p)
}
func (f *fakeVault) List(_ context.Context, p string) (*vault.Secret, error) {
	return f.answer("list", p)
}
func (f *fakeVault) Write(_ context.Context, p string, _ map[string]any) (*vault.Secret, error) {
	return f.answer("write", p)
}

func refuse(context.Context, string, string) (net.Conn, error) { return nil, errors.New("i/o timeout") }

func mustChecks(t *testing.T, specs ...string) []Check {
	t.Helper()
	var out []Check
	for _, s := range specs {
		c, err := ParseCheck(s)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	return out
}

func TestLegitIdentityLeastPrivilege(t *testing.T) {
	fv := &fakeVault{allowed: map[string]bool{"read database/creds/orders-api": true}}
	r := &Runner{Scenario: "orders-api", Vault: fv, Dial: refuse, Mount: "kubernetes", Role: "orders-api", ExpectLogin: Allow}
	res := r.Run(context.Background(), mustChecks(t,
		"read|database/creds/orders-api|allow",
		"read|kv/data/orders-api/config|deny",
		"list|database/roles|deny",
		"write|sys/audit/x|deny|{}",
		"tcp|postgres.db.svc:5432|deny",
	))
	passed, failed := Summary(res)
	if passed != 6 || failed != 0 {
		t.Fatalf("passed=%d failed=%d %+v", passed, failed, res)
	}
	if res[2].Status != 403 || res[2].Allowed {
		t.Fatalf("denied read should carry 403: %+v", res[2])
	}
}

func TestWrongServiceAccountDenied(t *testing.T) {
	fv := &fakeVault{loginErr: &vault.ResponseError{StatusCode: 403, Errors: []string{"service account name not authorized"}}}
	r := &Runner{Scenario: "intruder", Vault: fv, Dial: refuse, Role: "orders-api", ExpectLogin: Deny}
	res := r.Run(context.Background(), mustChecks(t, "read|database/creds/orders-api|deny", "tcp|x:1|deny"))
	if !res[0].Pass || res[0].Status != 403 {
		t.Fatalf("login result %+v", res[0])
	}
	if res[1].Pass || res[1].Error != "skipped: not logged in" {
		t.Fatalf("vault checks without a token are reported as failures, got %+v", res[1])
	}
	if !res[2].Pass {
		t.Fatalf("tcp checks still run: %+v", res[2])
	}
}

func TestUnexpectedOutcomesFail(t *testing.T) {
	fv := &fakeVault{allowed: map[string]bool{"read kv/data/x": true}}
	ok := func(context.Context, string, string) (net.Conn, error) {
		c1, c2 := net.Pipe()
		_ = c2.Close()
		return c1, nil
	}
	r := &Runner{Vault: fv, Dial: ok}
	res := r.Run(context.Background(), mustChecks(t, "read|kv/data/x|deny", "tcp|x:1|deny", "read|other|allow"))
	if _, failed := Summary(res); failed != 3 {
		t.Fatalf("want 3 failures, got %+v", res)
	}
}
