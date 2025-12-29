package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

const (
	stateLength       = 32
	codeVerifierBytes = 64
)

func NewState() (string, error) {
	return randomBase64URL(stateLength)
}

func NewNonce() (string, error) {
	return randomBase64URL(stateLength)
}

func NewCodeVerifier() (string, error) {
	return randomBase64URL(codeVerifierBytes)
}

func CodeChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func randomBase64URL(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to generate random value: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
