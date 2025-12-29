package oidc

import (
	"fmt"
	"net/url"
	"strings"
)

const defaultScopeOpenID = "openid"

var defaultScopes = []string{"openid", "profile", "email"}

type ProviderConfig struct {
	Name                 string   `json:"name"`
	IssuerURL            string   `json:"issuer_url"`
	ClientID             string   `json:"client_id"`
	ClientSecret         string   `json:"client_secret"`
	RedirectURI          string   `json:"redirect_uri"`
	Scopes               []string `json:"scopes"`
	Prompt               string   `json:"prompt,omitempty"`
	UsePKCE              *bool    `json:"use_pkce,omitempty"`
	AllowHTTPIssuer      bool     `json:"allow_http_issuer,omitempty"`
	AllowHTTPRedirect    bool     `json:"allow_http_redirect,omitempty"`
	AllowEmailLink       bool     `json:"allow_email_link,omitempty"`
	AutoCreateUser       bool     `json:"auto_create_user,omitempty"`
	AllowUnverifiedEmail bool     `json:"allow_unverified_email,omitempty"`
}

func (c ProviderConfig) PKCEEnabled() bool {
	if c.UsePKCE == nil {
		return true
	}
	return *c.UsePKCE
}

func (c ProviderConfig) Normalize() (ProviderConfig, error) {
	if strings.TrimSpace(c.Name) == "" {
		return c, fmt.Errorf("provider name is required")
	}
	if strings.TrimSpace(c.IssuerURL) == "" {
		return c, fmt.Errorf("issuer url is required")
	}
	if strings.TrimSpace(c.ClientID) == "" {
		return c, fmt.Errorf("client id is required")
	}
	if strings.TrimSpace(c.RedirectURI) == "" {
		return c, fmt.Errorf("redirect uri is required")
	}

	issuer, err := url.Parse(c.IssuerURL)
	if err != nil {
		return c, fmt.Errorf("invalid issuer url: %w", err)
	}
	if err := validateScheme(issuer, c.AllowHTTPIssuer); err != nil {
		return c, fmt.Errorf("issuer url %q %w", c.IssuerURL, err)
	}

	redirect, err := url.Parse(c.RedirectURI)
	if err != nil {
		return c, fmt.Errorf("invalid redirect uri: %w", err)
	}
	if err := validateScheme(redirect, c.AllowHTTPRedirect); err != nil {
		return c, fmt.Errorf("redirect uri %q %w", c.RedirectURI, err)
	}

	if !c.PKCEEnabled() && c.ClientSecret == "" {
		return c, fmt.Errorf("pkce is required for public clients")
	}

	if len(c.Scopes) == 0 {
		c.Scopes = append([]string{}, defaultScopes...)
	} else if !containsScope(c.Scopes, defaultScopeOpenID) {
		c.Scopes = append([]string{defaultScopeOpenID}, c.Scopes...)
	}

	return c, nil
}

func validateScheme(parsed *url.URL, allowHTTP bool) error {
	switch strings.ToLower(parsed.Scheme) {
	case "https":
		return nil
	case "http":
		if allowHTTP {
			return nil
		}
		return fmt.Errorf("must use https")
	default:
		return fmt.Errorf("unsupported scheme %q", parsed.Scheme)
	}
}

func normalizeIssuer(issuer string) string {
	return strings.TrimRight(issuer, "/")
}

func containsScope(scopes []string, scope string) bool {
	for _, existing := range scopes {
		if existing == scope {
			return true
		}
	}
	return false
}
