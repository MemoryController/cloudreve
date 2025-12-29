package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
)

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

func (s *jwkSet) Key(kid string) *jwk {
	for i := range s.Keys {
		if s.Keys[i].Kid == kid {
			return &s.Keys[i]
		}
	}
	return nil
}

func (k *jwk) PublicKey() (interface{}, error) {
	switch k.Kty {
	case "RSA":
		return k.rsaPublicKey()
	case "EC":
		return k.ecdsaPublicKey()
	default:
		return nil, fmt.Errorf("unsupported key type %q", k.Kty)
	}
}

func (k *jwk) rsaPublicKey() (*rsa.PublicKey, error) {
	nBytes, err := decodeBase64URL(k.N)
	if err != nil {
		return nil, fmt.Errorf("invalid rsa modulus: %w", err)
	}
	eBytes, err := decodeBase64URL(k.E)
	if err != nil {
		return nil, fmt.Errorf("invalid rsa exponent: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() {
		return nil, fmt.Errorf("rsa exponent too large")
	}

	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}

func (k *jwk) ecdsaPublicKey() (*ecdsa.PublicKey, error) {
	xBytes, err := decodeBase64URL(k.X)
	if err != nil {
		return nil, fmt.Errorf("invalid ecdsa x: %w", err)
	}
	yBytes, err := decodeBase64URL(k.Y)
	if err != nil {
		return nil, fmt.Errorf("invalid ecdsa y: %w", err)
	}

	curve, err := curveFromJWK(k.Crv)
	if err != nil {
		return nil, err
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}

func curveFromJWK(crv string) (elliptic.Curve, error) {
	switch crv {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported ecdsa curve %q", crv)
	}
}

func decodeBase64URL(value string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(value)
}
