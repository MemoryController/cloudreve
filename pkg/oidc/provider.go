package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const jwksCacheTTL = 5 * time.Minute

type Provider interface {
	Name() string
	Config() ProviderConfig
	AuthCodeURL(state, nonce, codeChallenge string) (string, error)
	Exchange(ctx context.Context, code, codeVerifier string) (*TokenResponse, error)
	VerifyIDToken(ctx context.Context, rawIDToken string) (*VerifiedIDToken, error)
}

type TokenResponse struct {
	AccessToken string `json:"access_token,omitempty"`
	TokenType   string `json:"token_type,omitempty"`
	ExpiresIn   int64  `json:"expires_in,omitempty"`
	IDToken     string `json:"id_token,omitempty"`
}

type discoveryDocument struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

type provider struct {
	config     ProviderConfig
	httpClient *http.Client
	discovery  *discoveryDocument
	jwksMu     sync.Mutex
	jwks       *jwkSet
	jwksAt     time.Time
}

func newProvider(ctx context.Context, httpClient *http.Client, config ProviderConfig) (Provider, error) {
	normalized, err := config.Normalize()
	if err != nil {
		return nil, err
	}

	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}

	discovery, err := discover(ctx, httpClient, normalized.IssuerURL)
	if err != nil {
		return nil, err
	}
	if normalizeIssuer(discovery.Issuer) != normalizeIssuer(normalized.IssuerURL) {
		return nil, fmt.Errorf("discovery issuer mismatch")
	}

	return &provider{
		config:     normalized,
		httpClient: httpClient,
		discovery:  discovery,
	}, nil
}

func (p *provider) Name() string {
	return p.config.Name
}

func (p *provider) Config() ProviderConfig {
	return p.config
}

func (p *provider) AuthCodeURL(state, nonce, codeChallenge string) (string, error) {
	if state == "" {
		return "", fmt.Errorf("state is required")
	}
	authURL, err := url.Parse(p.discovery.AuthorizationEndpoint)
	if err != nil {
		return "", fmt.Errorf("invalid authorization endpoint: %w", err)
	}

	query := authURL.Query()
	query.Set("response_type", "code")
	query.Set("client_id", p.config.ClientID)
	query.Set("redirect_uri", p.config.RedirectURI)
	query.Set("scope", strings.Join(p.config.Scopes, " "))
	query.Set("state", state)
	if nonce != "" {
		query.Set("nonce", nonce)
	}
	if p.config.Prompt != "" {
		query.Set("prompt", p.config.Prompt)
	}
	if codeChallenge != "" {
		query.Set("code_challenge", codeChallenge)
		query.Set("code_challenge_method", "S256")
	}
	authURL.RawQuery = query.Encode()
	return authURL.String(), nil
}

func (p *provider) Exchange(ctx context.Context, code, codeVerifier string) (*TokenResponse, error) {
	if code == "" {
		return nil, fmt.Errorf("authorization code is required")
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", p.config.RedirectURI)
	form.Set("client_id", p.config.ClientID)
	if codeVerifier != "" {
		form.Set("code_verifier", codeVerifier)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.discovery.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if p.config.ClientSecret != "" {
		req.SetBasicAuth(p.config.ClientID, p.config.ClientSecret)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("token endpoint returned status %d", resp.StatusCode)
	}

	var token TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}
	if token.IDToken == "" {
		return nil, fmt.Errorf("id token missing from response")
	}
	return &token, nil
}

func (p *provider) VerifyIDToken(ctx context.Context, rawIDToken string) (*VerifiedIDToken, error) {
	claims := &idTokenClaims{}
	parser := jwt.NewParser(jwt.WithValidMethods(validSigningMethods()))
	token, err := parser.ParseWithClaims(rawIDToken, claims, func(token *jwt.Token) (interface{}, error) {
		return p.keyForToken(ctx, token)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse id token: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid id token")
	}

	meta := TokenMeta{
		Issuer:   claims.Issuer,
		Subject:  claims.Subject,
		Audience: claims.Audience,
	}
	if claims.ExpiresAt != nil {
		meta.Expiry = claims.ExpiresAt.Time
	}

	return &VerifiedIDToken{
		Meta:   meta,
		Claims: &claims.IDTokenClaims,
	}, nil
}

func (p *provider) keyForToken(ctx context.Context, token *jwt.Token) (interface{}, error) {
	kid, _ := token.Header["kid"].(string)
	if kid == "" {
		return nil, fmt.Errorf("kid missing in token header")
	}
	jwk, err := p.getKey(ctx, kid)
	if err != nil {
		return nil, err
	}
	return jwk.PublicKey()
}

func (p *provider) getKey(ctx context.Context, kid string) (*jwk, error) {
	jwks, err := p.getJWKS(ctx, false)
	if err != nil {
		return nil, err
	}
	if key := jwks.Key(kid); key != nil {
		return key, nil
	}

	jwks, err = p.getJWKS(ctx, true)
	if err != nil {
		return nil, err
	}
	if key := jwks.Key(kid); key != nil {
		return key, nil
	}

	return nil, fmt.Errorf("jwks key %q not found", kid)
}

func (p *provider) getJWKS(ctx context.Context, force bool) (*jwkSet, error) {
	p.jwksMu.Lock()
	defer p.jwksMu.Unlock()

	if !force && p.jwks != nil && time.Since(p.jwksAt) < jwksCacheTTL {
		return p.jwks, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.discovery.JWKSURI, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build jwks request: %w", err)
	}
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jwks request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("jwks endpoint returned status %d", resp.StatusCode)
	}

	var set jwkSet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return nil, fmt.Errorf("failed to decode jwks response: %w", err)
	}

	p.jwks = &set
	p.jwksAt = time.Now()
	return p.jwks, nil
}

func discover(ctx context.Context, client *http.Client, issuerURL string) (*discoveryDocument, error) {
	issuer := strings.TrimRight(issuerURL, "/")
	discoveryURL := issuer + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build discovery request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discovery request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("discovery endpoint returned status %d", resp.StatusCode)
	}

	var document discoveryDocument
	if err := json.NewDecoder(resp.Body).Decode(&document); err != nil {
		return nil, fmt.Errorf("failed to decode discovery document: %w", err)
	}
	if document.Issuer == "" || document.AuthorizationEndpoint == "" || document.TokenEndpoint == "" || document.JWKSURI == "" {
		return nil, fmt.Errorf("discovery document missing required fields")
	}

	return &document, nil
}

func validSigningMethods() []string {
	return []string{
		jwt.SigningMethodRS256.Alg(),
		jwt.SigningMethodRS384.Alg(),
		jwt.SigningMethodRS512.Alg(),
		jwt.SigningMethodES256.Alg(),
		jwt.SigningMethodES384.Alg(),
		jwt.SigningMethodES512.Alg(),
	}
}
