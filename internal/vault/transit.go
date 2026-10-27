package vault

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
)

// Transit is encryption as a service with a named key on a transit mount.
// The key never leaves Vault; the application only sees ciphertext.
type Transit struct {
	Client *Client
	Mount  string
	Key    string
}

// Encrypt returns Vault ciphertext ("vault:v<N>:...") for plaintext.
func (t *Transit) Encrypt(ctx context.Context, plaintext []byte) (string, error) {
	s, err := t.Client.Write(ctx, t.Mount+"/encrypt/"+t.Key, map[string]any{
		"plaintext": base64.StdEncoding.EncodeToString(plaintext),
	})
	if err != nil {
		return "", err
	}
	ct := s.StringField("ciphertext")
	if ct == "" {
		return "", errors.New("vault: transit encrypt returned no ciphertext")
	}
	return ct, nil
}

// Decrypt returns the plaintext for Vault ciphertext.
func (t *Transit) Decrypt(ctx context.Context, ciphertext string) ([]byte, error) {
	s, err := t.Client.Write(ctx, t.Mount+"/decrypt/"+t.Key, map[string]any{"ciphertext": ciphertext})
	if err != nil {
		return nil, err
	}
	pt, err := base64.StdEncoding.DecodeString(s.StringField("plaintext"))
	if err != nil {
		return nil, fmt.Errorf("vault: transit decrypt: %w", err)
	}
	return pt, nil
}
