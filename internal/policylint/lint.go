// Package policylint enforces least-privilege rules on Vault ACL policies kept
// as HCL in the repository. It is deliberately strict: application policies
// must name exact paths, must not touch sys/ or auth/, and must not use sudo.
//
// A reviewed exception is declared on the line directly above the path block:
//
//	# policylint:allow wildcard,privileged-path -- reason the exception is safe
//
// An exception without a reason is itself a finding.
package policylint

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Finding is one rule violation.
type Finding struct {
	Path string // policy path the finding refers to ("" for file-level)
	Rule string
	Msg  string
}

func (f Finding) String() string {
	if f.Path == "" {
		return fmt.Sprintf("[%s] %s", f.Rule, f.Msg)
	}
	return fmt.Sprintf("[%s] path %q: %s", f.Rule, f.Path, f.Msg)
}

var (
	blockRe   = regexp.MustCompile(`(?s)path\s+"([^"]+)"\s*\{(.*?)\}`)
	capsRe    = regexp.MustCompile(`(?s)capabilities\s*=\s*\[(.*?)\]`)
	commentRe = regexp.MustCompile(`(?m)^\s*(#|//).*$`)
	quotedRe  = regexp.MustCompile(`"([^"]*)"`)
	allowRe   = regexp.MustCompile(`^\s*#\s*policylint:allow\s+([a-z,-]+)\s*(?:--\s*(.*))?$`)
	pathRe    = regexp.MustCompile(`^\s*path\s+"([^"]+)"`)

	allowedCaps = []string{"create", "read", "update", "patch", "delete", "list", "deny"}
)

// exceptions maps a policy path to the rules allowed for it.
func exceptions(src string) (map[string][]string, []Finding) {
	allowed := map[string][]string{}
	var out []Finding
	var pending []string
	for _, line := range strings.Split(src, "\n") {
		if m := allowRe.FindStringSubmatch(line); m != nil {
			if strings.TrimSpace(m[2]) == "" {
				out = append(out, Finding{Rule: "exception", Msg: "policylint:allow needs a reason after --"})
				pending = nil
				continue
			}
			pending = strings.Split(m[1], ",")
			continue
		}
		if m := pathRe.FindStringSubmatch(line); m != nil {
			if pending != nil {
				allowed[m[1]] = pending
			}
		}
		if strings.TrimSpace(line) != "" {
			pending = nil
		}
	}
	return allowed, out
}

// Lint checks one policy document.
func Lint(src string) []Finding {
	allowed, exFindings := exceptions(src)
	var out []Finding
	for _, f := range lint(src) {
		if f.Path != "" && slices.Contains(allowed[f.Path], f.Rule) {
			continue
		}
		out = append(out, f)
	}
	return append(exFindings, out...)
}

func lint(src string) []Finding {
	var out []Finding
	body := commentRe.ReplaceAllString(src, "")
	blocks := blockRe.FindAllStringSubmatch(body, -1)
	if len(blocks) == 0 {
		return []Finding{{Rule: "empty", Msg: "policy has no path blocks"}}
	}
	if rest := strings.TrimSpace(blockRe.ReplaceAllString(body, "")); rest != "" {
		out = append(out, Finding{Rule: "unparsed", Msg: fmt.Sprintf("content outside path blocks: %.40q", rest)})
	}
	seen := map[string]bool{}
	for _, b := range blocks {
		path, inner := b[1], b[2]
		if seen[path] {
			out = append(out, Finding{Path: path, Rule: "duplicate", Msg: "path declared twice"})
		}
		seen[path] = true
		if strings.ContainsAny(path, "*+") {
			out = append(out, Finding{Path: path, Rule: "wildcard", Msg: "globs and segment wildcards are not allowed; name the exact path"})
		}
		if strings.HasPrefix(path, "sys/") || strings.HasPrefix(path, "auth/") {
			out = append(out, Finding{Path: path, Rule: "privileged-path", Msg: "application policies must not grant sys/ or auth/ paths"})
		}
		m := capsRe.FindStringSubmatch(inner)
		if m == nil {
			out = append(out, Finding{Path: path, Rule: "capabilities", Msg: "missing capabilities"})
			continue
		}
		caps := quotedRe.FindAllStringSubmatch(m[1], -1)
		if len(caps) == 0 {
			out = append(out, Finding{Path: path, Rule: "capabilities", Msg: "empty capabilities"})
		}
		for _, c := range caps {
			switch {
			case c[1] == "sudo":
				out = append(out, Finding{Path: path, Rule: "sudo", Msg: "sudo is not allowed"})
			case !slices.Contains(allowedCaps, c[1]):
				out = append(out, Finding{Path: path, Rule: "capabilities", Msg: fmt.Sprintf("unknown capability %q", c[1])})
			}
		}
		if extra := strings.TrimSpace(capsRe.ReplaceAllString(inner, "")); extra != "" {
			out = append(out, Finding{Path: path, Rule: "parameters", Msg: "only capabilities are allowed in a block; restrict parameters with roles instead"})
		}
	}
	return out
}
