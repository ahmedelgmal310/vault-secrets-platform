// Package vault is a small, dependency-free client for the subset of the
// Vault HTTP API this project uses: Kubernetes auth login, token renewal,
// reading and writing logical paths, and lease renewal and revocation.
package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Secret is the common envelope of a Vault API response.
type Secret struct {
	RequestID     string         `json:"request_id"`
	LeaseID       string         `json:"lease_id"`
	LeaseDuration int            `json:"lease_duration"`
	Renewable     bool           `json:"renewable"`
	Data          map[string]any `json:"data"`
	Warnings      []string       `json:"warnings"`
	Auth          *Auth          `json:"auth"`
}

// Auth is the auth block returned by login and token renewal.
type Auth struct {
	ClientToken   string            `json:"client_token"`
	Accessor      string            `json:"accessor"`
	Policies      []string          `json:"policies"`
	TokenPolicies []string          `json:"token_policies"`
	Metadata      map[string]string `json:"metadata"`
	LeaseDuration int               `json:"lease_duration"`
	Renewable     bool              `json:"renewable"`
}

// TTL returns the lease duration as a time.Duration.
func (s *Secret) TTL() time.Duration { return time.Duration(s.LeaseDuration) * time.Second }

// TTL returns the token lease duration as a time.Duration.
func (a *Auth) TTL() time.Duration { return time.Duration(a.LeaseDuration) * time.Second }

// ResponseError is returned for any non-2xx response.
type ResponseError struct {
	StatusCode int
	Method     string
	Path       string
	Errors     []string
}

func (e *ResponseError) Error() string {
	msg := strings.Join(e.Errors, "; ")
	if msg == "" {
		msg = http.StatusText(e.StatusCode)
	}
	return fmt.Sprintf("vault: %s %s: HTTP %d: %s", e.Method, e.Path, e.StatusCode, msg)
}

// StatusCode extracts the HTTP status from a *ResponseError, or 0.
func StatusCode(err error) int {
	var re *ResponseError
	if errors.As(err, &re) {
		return re.StatusCode
	}
	return 0
}

// Client talks to one Vault address. It is safe for concurrent use.
type Client struct {
	addr string
	http *http.Client

	mu    sync.RWMutex
	token string
}

// New returns a client for addr (for example http://vault-active.vault.svc:8200).
// A nil httpClient uses a client with a 10s timeout.
func New(addr string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &Client{addr: strings.TrimRight(addr, "/"), http: httpClient}
}

// SetToken sets the token sent in X-Vault-Token.
func (c *Client) SetToken(t string) {
	c.mu.Lock()
	c.token = t
	c.mu.Unlock()
}

// Token returns the current token.
func (c *Client) Token() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.token
}

// LoginKubernetes exchanges a service account JWT for a Vault token using the
// Kubernetes auth method mounted at mount, and stores the token on success.
func (c *Client) LoginKubernetes(ctx context.Context, mount, role, jwt string) (*Auth, error) {
	s, err := c.do(ctx, http.MethodPost, "auth/"+mount+"/login", map[string]any{"role": role, "jwt": jwt}, false)
	if err != nil {
		return nil, err
	}
	if s.Auth == nil || s.Auth.ClientToken == "" {
		return nil, errors.New("vault: login response has no auth block")
	}
	c.SetToken(s.Auth.ClientToken)
	return s.Auth, nil
}

// RenewSelf renews the client's own token.
func (c *Client) RenewSelf(ctx context.Context, increment time.Duration) (*Auth, error) {
	s, err := c.do(ctx, http.MethodPost, "auth/token/renew-self", map[string]any{"increment": int(increment.Seconds())}, true)
	if err != nil {
		return nil, err
	}
	if s.Auth == nil {
		return nil, errors.New("vault: renew-self response has no auth block")
	}
	return s.Auth, nil
}

// Read performs a GET on a logical path such as database/creds/orders-api.
func (c *Client) Read(ctx context.Context, path string) (*Secret, error) {
	return c.do(ctx, http.MethodGet, path, nil, true)
}

// Write performs a POST on a logical path with a JSON body.
func (c *Client) Write(ctx context.Context, path string, body map[string]any) (*Secret, error) {
	return c.do(ctx, http.MethodPost, path, body, true)
}

// List performs a LIST on a logical path.
func (c *Client) List(ctx context.Context, path string) (*Secret, error) {
	return c.do(ctx, "LIST", path, nil, true)
}

// RenewLease extends a lease by increment (Vault may grant less, capped by max_ttl).
func (c *Client) RenewLease(ctx context.Context, leaseID string, increment time.Duration) (*Secret, error) {
	return c.do(ctx, http.MethodPut, "sys/leases/renew", map[string]any{"lease_id": leaseID, "increment": int(increment.Seconds())}, true)
}

// RevokeLease revokes a lease immediately. It uses the sys/leases/revoke/<id>
// form so a policy can scope revocation to one secrets path.
func (c *Client) RevokeLease(ctx context.Context, leaseID string) error {
	if leaseID == "" || strings.Contains(leaseID, "..") {
		return errors.New("vault: invalid lease id")
	}
	_, err := c.do(ctx, http.MethodPut, "sys/leases/revoke/"+strings.TrimLeft(leaseID, "/"), map[string]any{}, true)
	return err
}

func (c *Client) do(ctx context.Context, method, path string, body map[string]any, auth bool) (*Secret, error) {
	path = strings.TrimLeft(path, "/")
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("vault: encode body: %w", err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.addr+"/v1/"+path, rd)
	if err != nil {
		return nil, fmt.Errorf("vault: build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth {
		if t := c.Token(); t != "" {
			req.Header.Set("X-Vault-Token", t)
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault: %s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("vault: read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		re := &ResponseError{StatusCode: resp.StatusCode, Method: method, Path: path}
		var eb struct {
			Errors []string `json:"errors"`
		}
		if json.Unmarshal(raw, &eb) == nil {
			re.Errors = eb.Errors
		}
		return nil, re
	}
	s := &Secret{}
	if len(bytes.TrimSpace(raw)) == 0 {
		return s, nil
	}
	if err := json.Unmarshal(raw, s); err != nil {
		return nil, fmt.Errorf("vault: decode response: %w", err)
	}
	return s, nil
}

// StringField returns data[key] as a string, or "" when missing or not a string.
func (s *Secret) StringField(key string) string {
	if s == nil || s.Data == nil {
		return ""
	}
	v, _ := s.Data[key].(string)
	return v
}
