package oidc

import (
	"fmt"
	"time"
)

type TokenMeta struct {
	Issuer   string
	Subject  string
	Audience []string
	Expiry   time.Time
}

type TokenValidator struct {
	ExpectedIssuer string
	ClientID       string
	Now            func() time.Time
}

func (v TokenValidator) Validate(meta TokenMeta, claims *IDTokenClaims, expectedNonce string) error {
	if claims == nil {
		return fmt.Errorf("claims are required")
	}
	if meta.Subject == "" {
		return fmt.Errorf("subject is required")
	}
	if v.ExpectedIssuer != "" && normalizeIssuer(meta.Issuer) != normalizeIssuer(v.ExpectedIssuer) {
		return fmt.Errorf("issuer mismatch")
	}
	if v.ClientID != "" && !audienceContains(meta.Audience, v.ClientID) {
		return fmt.Errorf("audience mismatch")
	}
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	if !meta.Expiry.IsZero() && meta.Expiry.Before(now) {
		return fmt.Errorf("token expired")
	}
	if expectedNonce != "" && claims.Nonce != expectedNonce {
		return fmt.Errorf("nonce mismatch")
	}
	return nil
}

func audienceContains(audience []string, clientID string) bool {
	for _, aud := range audience {
		if aud == clientID {
			return true
		}
	}
	return false
}
