// Package probe runs access checks against Vault (and plain TCP) from inside a
// pod, compares each outcome with an expectation, and reports JSON results. CI
// uses it to prove that least privilege holds: the right identity gets exactly
// what its policy grants and every other attempt is denied.
package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/ahmedelgmal310/vault-secrets-platform/internal/vault"
)

// Expectations.
const (
	Allow = "allow"
	Deny  = "deny"
)

// Check is one access attempt.
type Check struct {
	Op     string // read, list, write, tcp
	Target string // Vault path, or host:port for tcp
	Expect string // allow or deny
	Body   map[string]any
}

// String renders the check in the same form ParseCheck accepts (without body).
func (c Check) String() string { return c.Op + " " + c.Target }

// ParseCheck parses "op|target|expect" or "write|path|expect|{json body}".
func ParseCheck(s string) (Check, error) {
	parts := strings.SplitN(s, "|", 4)
	if len(parts) < 3 {
		return Check{}, fmt.Errorf("check %q: want op|target|expect[|json]", s)
	}
	c := Check{Op: parts[0], Target: parts[1], Expect: parts[2]}
	switch c.Op {
	case "read", "list", "write", "tcp":
	default:
		return Check{}, fmt.Errorf("check %q: unknown op %q", s, c.Op)
	}
	if c.Expect != Allow && c.Expect != Deny {
		return Check{}, fmt.Errorf("check %q: expect must be allow or deny", s)
	}
	if c.Target == "" {
		return Check{}, fmt.Errorf("check %q: empty target", s)
	}
	if len(parts) == 4 {
		if err := json.Unmarshal([]byte(parts[3]), &c.Body); err != nil {
			return Check{}, fmt.Errorf("check %q: body: %w", s, err)
		}
	}
	return c, nil
}

// Result is the outcome of one check.
type Result struct {
	Scenario string `json:"scenario"`
	Check    string `json:"check"`
	Expect   string `json:"expect"`
	Allowed  bool   `json:"allowed"`
	Status   int    `json:"status,omitempty"`
	Error    string `json:"error,omitempty"`
	Pass     bool   `json:"pass"`
}

// Vault is the subset of the Vault client used by the probe.
type Vault interface {
	LoginKubernetes(ctx context.Context, mount, role, jwt string) (*vault.Auth, error)
	Read(ctx context.Context, path string) (*vault.Secret, error)
	List(ctx context.Context, path string) (*vault.Secret, error)
	Write(ctx context.Context, path string, body map[string]any) (*vault.Secret, error)
}

// Dialer opens TCP connections (net.Dialer in production).
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

// Runner executes a scenario.
type Runner struct {
	Scenario string
	Vault    Vault
	Dial     Dialer
	Mount    string
	Role     string
	JWT      string
	// ExpectLogin is allow or deny; empty skips the login step.
	ExpectLogin string
	Timeout     time.Duration
}

// Run performs the login (if configured) and every check.
func (r *Runner) Run(ctx context.Context, checks []Check) []Result {
	if r.Timeout == 0 {
		r.Timeout = 5 * time.Second
	}
	var out []Result
	loggedIn := false
	if r.ExpectLogin != "" {
		cctx, cancel := context.WithTimeout(ctx, r.Timeout)
		_, err := r.Vault.LoginKubernetes(cctx, r.Mount, r.Role, r.JWT)
		cancel()
		loggedIn = err == nil
		out = append(out, r.result("login "+r.Mount+"/role/"+r.Role, r.ExpectLogin, err))
	}
	for _, c := range checks {
		if c.Op != "tcp" && r.ExpectLogin != "" && !loggedIn {
			out = append(out, Result{Scenario: r.Scenario, Check: c.String(), Expect: c.Expect, Error: "skipped: not logged in"})
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, r.Timeout)
		err := r.attempt(cctx, c)
		cancel()
		out = append(out, r.result(c.String(), c.Expect, err))
	}
	return out
}

func (r *Runner) attempt(ctx context.Context, c Check) error {
	var err error
	switch c.Op {
	case "read":
		_, err = r.Vault.Read(ctx, c.Target)
	case "list":
		_, err = r.Vault.List(ctx, c.Target)
	case "write":
		_, err = r.Vault.Write(ctx, c.Target, c.Body)
	case "tcp":
		var conn net.Conn
		conn, err = r.Dial(ctx, "tcp", c.Target)
		if err == nil {
			_ = conn.Close()
		}
	}
	return err
}

func (r *Runner) result(check, expect string, err error) Result {
	res := Result{Scenario: r.Scenario, Check: check, Expect: expect, Allowed: err == nil}
	if err != nil {
		res.Status = vault.StatusCode(err)
		res.Error = err.Error()
	}
	res.Pass = (expect == Allow) == res.Allowed
	return res
}

// Summary counts passes and failures.
func Summary(rs []Result) (passed, failed int) {
	for _, r := range rs {
		if r.Pass {
			passed++
		} else {
			failed++
		}
	}
	return passed, failed
}
