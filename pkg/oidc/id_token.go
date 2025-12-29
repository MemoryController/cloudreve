package oidc

import "github.com/golang-jwt/jwt/v5"

type idTokenClaims struct {
	jwt.RegisteredClaims
	IDTokenClaims
}
