package oidc

import "strings"

type IDTokenClaims struct {
	Email             string `json:"email,omitempty"`
	EmailVerified     bool   `json:"email_verified,omitempty"`
	Name              string `json:"name,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Picture           string `json:"picture,omitempty"`
	Nonce             string `json:"nonce,omitempty"`
}

type Identity struct {
	Provider      string
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	Avatar        string
}

type VerifiedIDToken struct {
	Meta   TokenMeta
	Claims *IDTokenClaims
}

func IdentityFromToken(providerName string, meta TokenMeta, claims *IDTokenClaims) Identity {
	name := claims.Name
	if name == "" {
		name = claims.PreferredUsername
	}

	return Identity{
		Provider:      providerName,
		Issuer:        meta.Issuer,
		Subject:       meta.Subject,
		Email:         strings.ToLower(strings.TrimSpace(claims.Email)),
		EmailVerified: claims.EmailVerified,
		Name:          strings.TrimSpace(name),
		Avatar:        strings.TrimSpace(claims.Picture),
	}
}

func (i Identity) DisplayName() string {
	if i.Name != "" {
		return i.Name
	}
	if i.Email != "" {
		if at := strings.IndexByte(i.Email, '@'); at > 0 {
			return i.Email[:at]
		}
		return i.Email
	}
	return "oidc-user"
}
