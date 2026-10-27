// Command policylint checks Vault ACL policy files for least-privilege
// violations and exits non-zero when it finds any.
//
//	go run ./cmd/policylint terraform/policies/*.hcl
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/ahmedelgmal310/vault-secrets-platform/internal/policylint"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.ReadFile))
}

func run(files []string, out io.Writer, readFile func(string) ([]byte, error)) int {
	if len(files) == 0 {
		_, _ = fmt.Fprintln(out, "usage: policylint FILE...")
		return 2
	}
	bad := 0
	for _, f := range files {
		src, err := readFile(f)
		if err != nil {
			_, _ = fmt.Fprintf(out, "%s: %v\n", f, err)
			return 2
		}
		findings := policylint.Lint(string(src))
		for _, fd := range findings {
			_, _ = fmt.Fprintf(out, "%s: %s\n", f, fd)
		}
		if len(findings) == 0 {
			_, _ = fmt.Fprintf(out, "%s: ok\n", f)
		}
		bad += len(findings)
	}
	if bad > 0 {
		return 1
	}
	return 0
}
