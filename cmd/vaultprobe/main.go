// Command vaultprobe runs a scenario of access checks against Vault from inside
// a pod and prints one JSON line per check. It exits non-zero when any outcome
// differs from its expectation. See internal/probe for the check syntax.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/ahmedelgmal310/vault-secrets-platform/internal/probe"
	"github.com/ahmedelgmal310/vault-secrets-platform/internal/vault"
)

type checkList []string

func (c *checkList) String() string     { return strings.Join(*c, ",") }
func (c *checkList) Set(v string) error { *c = append(*c, v); return nil }

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.ReadFile))
}

func run(ctx context.Context, args []string, stdout io.Writer, readFile func(string) ([]byte, error)) int {
	fs := flag.NewFlagSet("vaultprobe", flag.ContinueOnError)
	fs.SetOutput(stdout)
	scenario := fs.String("scenario", "default", "scenario name used in the output")
	addr := fs.String("addr", "http://vault-active.vault.svc:8200", "Vault address")
	mount := fs.String("mount", "kubernetes", "Kubernetes auth mount")
	role := fs.String("role", "", "Vault role to log in as")
	jwtPath := fs.String("jwt", "/var/run/secrets/vault/token", "projected service account token")
	expectLogin := fs.String("expect-login", "", "allow or deny; empty skips login")
	var checks checkList
	fs.Var(&checks, "check", "op|target|expect[|json] (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	var parsed []probe.Check
	for _, s := range checks {
		c, err := probe.ParseCheck(s)
		if err != nil {
			_, _ = fmt.Fprintln(stdout, err)
			return 2
		}
		parsed = append(parsed, c)
	}
	jwt := ""
	if *expectLogin != "" {
		b, err := readFile(*jwtPath)
		if err != nil {
			_, _ = fmt.Fprintln(stdout, "read token:", err)
			return 2
		}
		jwt = strings.TrimSpace(string(b))
	}
	var d net.Dialer
	r := &probe.Runner{
		Scenario:    *scenario,
		Vault:       vault.New(*addr, nil),
		Dial:        d.DialContext,
		Mount:       *mount,
		Role:        *role,
		JWT:         jwt,
		ExpectLogin: *expectLogin,
	}
	results := r.Run(ctx, parsed)
	enc := json.NewEncoder(stdout)
	for _, res := range results {
		_ = enc.Encode(res)
	}
	passed, failed := probe.Summary(results)
	_ = enc.Encode(map[string]any{"scenario": *scenario, "summary": true, "passed": passed, "failed": failed})
	if failed > 0 {
		return 1
	}
	return 0
}
