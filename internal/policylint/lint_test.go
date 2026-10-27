package policylint

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func rules(fs []Finding) string {
	var r []string
	for _, f := range fs {
		r = append(r, f.Rule)
	}
	return strings.Join(r, ",")
}

func TestCleanPolicy(t *testing.T) {
	src := `
# comment
path "database/creds/app" {
  capabilities = ["read"]
}
path "transit/encrypt/app" { capabilities = ["update"] }
`
	if fs := Lint(src); len(fs) != 0 {
		t.Fatalf("unexpected findings: %v", fs)
	}
}

func TestViolations(t *testing.T) {
	cases := map[string]string{
		`path "kv/data/*" { capabilities = ["read"] }`:                                       "wildcard",
		`path "kv/+/x" { capabilities = ["read"] }`:                                          "wildcard",
		`path "sys/mounts" { capabilities = ["read"] }`:                                      "privileged-path",
		`path "auth/token/create" { capabilities = ["update"] }`:                             "privileged-path",
		`path "secret/x" { capabilities = ["read", "sudo"] }`:                                "sudo",
		`path "secret/x" { capabilities = ["root"] }`:                                        "capabilities",
		`path "secret/x" { capabilities = [] }`:                                              "capabilities",
		`path "secret/x" { }`:                                                                "capabilities",
		`path "secret/x" { capabilities = ["read"] allowed_parameters = {} }`:                "parameters",
		"path \"a\" { capabilities = [\"read\"] }\npath \"a\" { capabilities = [\"list\"] }": "duplicate",
		`# nothing here`: "empty",
		"path \"a\" { capabilities = [\"read\"] }\nnot_a_block = true": "unparsed",
	}
	for src, want := range cases {
		if got := rules(Lint(src)); !strings.Contains(got, want) {
			t.Errorf("%q: got rules %q, want %q", src, got, want)
		}
	}
}

func TestExceptions(t *testing.T) {
	ok := "# policylint:allow wildcard,privileged-path -- scoped to one role\npath \"sys/leases/revoke/database/creds/app/*\" { capabilities = [\"update\"] }"
	if fs := Lint(ok); len(fs) != 0 {
		t.Fatalf("exception with reason should suppress: %v", fs)
	}
	noReason := "# policylint:allow wildcard\npath \"kv/*\" { capabilities = [\"read\"] }"
	if got := rules(Lint(noReason)); !strings.Contains(got, "exception") || !strings.Contains(got, "wildcard") {
		t.Fatalf("exception without reason must not suppress: %q", got)
	}
	notAdjacent := "# policylint:allow wildcard -- reason\n\npath \"other\" { capabilities = [\"read\"] }\npath \"kv/*\" { capabilities = [\"read\"] }"
	if got := rules(Lint(notAdjacent)); got != "wildcard" {
		t.Fatalf("exception only applies to the next block: %q", got)
	}
	f := Finding{Path: "p", Rule: "r", Msg: "m"}
	if f.String() != `[r] path "p": m` || (Finding{Rule: "r", Msg: "m"}).String() != "[r] m" {
		t.Fatal("finding format")
	}
}

// TestRepositoryPolicies lints the policies Terraform actually applies.
func TestRepositoryPolicies(t *testing.T) {
	files, err := filepath.Glob("../../terraform/policies/*.hcl")
	if err != nil || len(files) == 0 {
		t.Fatalf("no policies found: %v", err)
	}
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if fs := Lint(string(src)); len(fs) != 0 {
			t.Errorf("%s: %v", f, fs)
		}
	}
}
