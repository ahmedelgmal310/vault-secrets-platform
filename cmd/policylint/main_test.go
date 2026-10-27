package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	files := map[string]string{
		"good.hcl": `path "database/creds/app" { capabilities = ["read"] }`,
		"bad.hcl":  `path "sys/*" { capabilities = ["sudo"] }`,
	}
	read := func(f string) ([]byte, error) {
		s, ok := files[f]
		if !ok {
			return nil, errors.New("no such file")
		}
		return []byte(s), nil
	}
	var out bytes.Buffer
	if code := run([]string{"good.hcl"}, &out, read); code != 0 || !strings.Contains(out.String(), "good.hcl: ok") {
		t.Fatalf("good: %d %s", code, out.String())
	}
	out.Reset()
	if code := run([]string{"good.hcl", "bad.hcl"}, &out, read); code != 1 || !strings.Contains(out.String(), "[sudo]") {
		t.Fatalf("bad: %d %s", code, out.String())
	}
	if code := run(nil, &out, read); code != 2 {
		t.Fatalf("usage: %d", code)
	}
	if code := run([]string{"missing.hcl"}, &out, read); code != 2 {
		t.Fatalf("missing: %d", code)
	}
}
