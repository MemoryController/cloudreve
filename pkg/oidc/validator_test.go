package oidc

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTokenValidator(t *testing.T) {
	now := time.Date(2024, 4, 10, 12, 0, 0, 0, time.UTC)
	meta := TokenMeta{
		Issuer:   "https://issuer.example.com",
		Subject:  "sub-123",
		Audience: []string{"client-id"},
		Expiry:   now.Add(5 * time.Minute),
	}
	claims := &IDTokenClaims{Nonce: "nonce-1"}

	validator := TokenValidator{
		ExpectedIssuer: "https://issuer.example.com/",
		ClientID:       "client-id",
		Now:            func() time.Time { return now },
	}

	require.NoError(t, validator.Validate(meta, claims, "nonce-1"))
}

func TestTokenValidatorFailures(t *testing.T) {
	now := time.Date(2024, 4, 10, 12, 0, 0, 0, time.UTC)
	validator := TokenValidator{
		ExpectedIssuer: "https://issuer.example.com",
		ClientID:       "client-id",
		Now:            func() time.Time { return now },
	}

	tests := []struct {
		name   string
		meta   TokenMeta
		claims *IDTokenClaims
		nonce  string
	}{
		{
			name: "issuer mismatch",
			meta: TokenMeta{
				Issuer:   "https://other.example.com",
				Subject:  "sub",
				Audience: []string{"client-id"},
				Expiry:   now.Add(time.Minute),
			},
			claims: &IDTokenClaims{Nonce: "n"},
			nonce:  "n",
		},
		{
			name: "audience mismatch",
			meta: TokenMeta{
				Issuer:   "https://issuer.example.com",
				Subject:  "sub",
				Audience: []string{"other"},
				Expiry:   now.Add(time.Minute),
			},
			claims: &IDTokenClaims{Nonce: "n"},
			nonce:  "n",
		},
		{
			name: "expired",
			meta: TokenMeta{
				Issuer:   "https://issuer.example.com",
				Subject:  "sub",
				Audience: []string{"client-id"},
				Expiry:   now.Add(-time.Minute),
			},
			claims: &IDTokenClaims{Nonce: "n"},
			nonce:  "n",
		},
		{
			name: "nonce mismatch",
			meta: TokenMeta{
				Issuer:   "https://issuer.example.com",
				Subject:  "sub",
				Audience: []string{"client-id"},
				Expiry:   now.Add(time.Minute),
			},
			claims: &IDTokenClaims{Nonce: "n1"},
			nonce:  "n2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Error(t, validator.Validate(tt.meta, tt.claims, tt.nonce))
		})
	}
}
