package user

import (
	"context"
	"encoding/gob"
	"fmt"
	"strings"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/pkg/oidc"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/cloudreve/Cloudreve/v4/pkg/setting"
	"github.com/gin-gonic/gin"
)

const (
	oidcStatePrefix = "oidc_state_"
	oidcStateTTL    = 600
)

type oidcLoginState struct {
	Provider     string
	Nonce        string
	CodeVerifier string
}

func init() {
	gob.Register(oidcLoginState{})
}

type (
	OIDCStartParameterCtx struct{}
	OIDCStartService      struct {
		Provider string `uri:"provider" binding:"required"`
	}

	OIDCCallbackParameterCtx struct{}
	OIDCCallbackService      struct {
		Code             string `form:"code"`
		State            string `form:"state" binding:"required"`
		Error            string `form:"error"`
		ErrorDescription string `form:"error_description"`
	}
)

func (s *OIDCStartService) Start(c *gin.Context) (string, error) {
	dep := dependency.FromContext(c)
	config, err := getOIDCProviderConfig(c, dep.SettingProvider(), s.Provider)
	if err != nil {
		return "", err
	}

	provider, err := dep.OIDCManager().Provider(c, config)
	if err != nil {
		return "", serializer.NewError(serializer.CodeInternalSetting, "Failed to initialize OIDC provider", err)
	}

	state, err := oidc.NewState()
	if err != nil {
		return "", serializer.NewError(serializer.CodeInternalSetting, "Failed to generate login state", err)
	}
	nonce, err := oidc.NewNonce()
	if err != nil {
		return "", serializer.NewError(serializer.CodeInternalSetting, "Failed to generate login nonce", err)
	}

	var codeVerifier string
	var codeChallenge string
	if provider.Config().PKCEEnabled() {
		codeVerifier, err = oidc.NewCodeVerifier()
		if err != nil {
			return "", serializer.NewError(serializer.CodeInternalSetting, "Failed to generate code verifier", err)
		}
		codeChallenge = oidc.CodeChallengeS256(codeVerifier)
	}

	if err := dep.KV().Set(oidcStatePrefix+state, oidcLoginState{
		Provider:     s.Provider,
		Nonce:        nonce,
		CodeVerifier: codeVerifier,
	}, oidcStateTTL); err != nil {
		return "", serializer.NewError(serializer.CodeInternalSetting, "Failed to store login state", err)
	}

	authURL, err := provider.AuthCodeURL(state, nonce, codeChallenge)
	if err != nil {
		return "", serializer.NewError(serializer.CodeInternalSetting, "Failed to build authorization url", err)
	}

	return authURL, nil
}

func (s *OIDCCallbackService) Finish(c *gin.Context, providerName string) (*ent.User, error) {
	if s.Error != "" {
		return nil, serializer.NewError(serializer.CodeCredentialInvalid, "OIDC authorization failed", fmt.Errorf("%s: %s", s.Error, s.ErrorDescription))
	}

	if s.Code == "" {
		return nil, serializer.NewError(serializer.CodeCredentialInvalid, "Authorization code is required", nil)
	}

	dep := dependency.FromContext(c)
	config, err := getOIDCProviderConfig(c, dep.SettingProvider(), providerName)
	if err != nil {
		return nil, err
	}

	stateValue, ok := dep.KV().Get(oidcStatePrefix + s.State)
	if !ok {
		return nil, serializer.NewError(serializer.CodeCredentialInvalid, "Login state expired or invalid", nil)
	}
	_ = dep.KV().Delete(oidcStatePrefix, s.State)

	loginState, ok := stateValue.(oidcLoginState)
	if !ok || loginState.Provider != providerName {
		return nil, serializer.NewError(serializer.CodeCredentialInvalid, "Login state mismatch", nil)
	}

	provider, err := dep.OIDCManager().Provider(c, config)
	if err != nil {
		return nil, serializer.NewError(serializer.CodeInternalSetting, "Failed to initialize OIDC provider", err)
	}

	token, err := provider.Exchange(c, s.Code, loginState.CodeVerifier)
	if err != nil {
		return nil, serializer.NewError(serializer.CodeCredentialInvalid, "Failed to exchange code", err)
	}

	verifiedToken, err := provider.VerifyIDToken(c, token.IDToken)
	if err != nil {
		return nil, serializer.NewError(serializer.CodeCredentialInvalid, "Failed to verify ID token", err)
	}

	validator := oidc.TokenValidator{
		ExpectedIssuer: config.IssuerURL,
		ClientID:       config.ClientID,
	}
	if err := validator.Validate(oidc.TokenMeta{
		Issuer:   verifiedToken.Meta.Issuer,
		Subject:  verifiedToken.Meta.Subject,
		Audience: verifiedToken.Meta.Audience,
		Expiry:   verifiedToken.Meta.Expiry,
	}, verifiedToken.Claims, loginState.Nonce); err != nil {
		return nil, serializer.NewError(serializer.CodeCredentialInvalid, "Invalid ID token claims", err)
	}

	identity := oidc.IdentityFromToken(providerName, verifiedToken.Meta, verifiedToken.Claims)
	userClient := dep.UserClient()
	identityClient := dep.UserIdentityClient()

	loginUser, err := resolveOIDCUser(c, userClient, identityClient, config, identity, dep.SettingProvider().DefaultGroup(c))
	if err != nil {
		return nil, err
	}

	return loginUser, nil
}

func getOIDCProviderConfig(ctx context.Context, settings setting.Provider, providerName string) (oidc.ProviderConfig, error) {
	for _, provider := range settings.OIDCProviders(ctx) {
		if provider.Name == providerName {
			return oidc.ProviderConfig{
				Name:                 provider.Name,
				IssuerURL:            provider.IssuerURL,
				ClientID:             provider.ClientID,
				ClientSecret:         provider.ClientSecret,
				RedirectURI:          provider.RedirectURI,
				Scopes:               provider.Scopes,
				Prompt:               provider.Prompt,
				UsePKCE:              provider.UsePKCE,
				AllowHTTPIssuer:      provider.AllowHTTPIssuer,
				AllowHTTPRedirect:    provider.AllowHTTPRedirect,
				AllowEmailLink:       provider.AllowEmailLink,
				AutoCreateUser:       provider.AutoCreateUser,
				AllowUnverifiedEmail: provider.AllowUnverifiedEmail,
			}, nil
		}
	}

	return oidc.ProviderConfig{}, serializer.NewError(serializer.CodeNotFound, "OIDC provider not found", nil)
}

func resolveOIDCUser(ctx context.Context, userClient inventory.UserClient, identityClient inventory.UserIdentityClient, config oidc.ProviderConfig, identity oidc.Identity, defaultGroupID int) (*ent.User, error) {
	ctx = context.WithValue(ctx, inventory.LoadUserGroup{}, true)

	if existingIdentity, err := identityClient.GetByIssuerSubject(ctx, identity.Issuer, identity.Subject); err == nil {
		loginUser, err := userClient.GetByID(ctx, existingIdentity.UserID)
		if err != nil {
			return nil, serializer.NewError(serializer.CodeUserNotFound, "User not found", err)
		}
		if err := validateLoginUser(loginUser); err != nil {
			return nil, err
		}

		email := identity.Email
		_, _ = identityClient.Update(ctx, existingIdentity, &inventory.UpdateUserIdentityArgs{
			Email:         &email,
			EmailVerified: &identity.EmailVerified,
			Name:          &identity.Name,
			Avatar:        &identity.Avatar,
		})

		return loginUser, nil
	} else if !ent.IsNotFound(err) {
		return nil, serializer.NewError(serializer.CodeDBError, "Failed to query identity", err)
	}

	if identity.Email == "" {
		return nil, serializer.NewError(serializer.CodeCredentialInvalid, "Email is required for OIDC login", nil)
	}
	if !identity.EmailVerified && !config.AllowUnverifiedEmail {
		return nil, serializer.NewError(serializer.CodeCredentialInvalid, "Email is not verified", nil)
	}

	var loginUser *ent.User
	if config.AllowEmailLink {
		userByEmail, err := userClient.GetByEmail(ctx, identity.Email)
		if err == nil {
			if err := validateLoginUser(userByEmail); err != nil {
				return nil, err
			}
			loginUser = userByEmail
		} else if !ent.IsNotFound(err) {
			return nil, serializer.NewError(serializer.CodeDBError, "Failed to query user", err)
		}
	}

	uc, tx, ctx, err := inventory.WithTx(ctx, userClient)
	if err != nil {
		return nil, serializer.NewError(serializer.CodeDBError, "Failed to start transaction", err)
	}
	ic, _ := inventory.InheritTx(ctx, identityClient)

	if loginUser == nil {
		if !config.AutoCreateUser {
			_ = inventory.Rollback(tx)
			return nil, serializer.NewError(serializer.CodeOpenIDNotLinked, "OIDC account is not linked", nil)
		}

		newUser, err := uc.Create(ctx, &inventory.NewUserArgs{
			Email:         identity.Email,
			Nick:          strings.TrimSpace(identity.DisplayName()),
			PlainPassword: "",
			Status:        user.StatusActive,
			GroupID:       defaultGroupID,
			Avatar:        identity.Avatar,
		})
		if err != nil {
			_ = inventory.Rollback(tx)
			return nil, serializer.NewError(serializer.CodeDBError, "Failed to create user", err)
		}
		loginUser = newUser
	}

	if _, err := ic.Create(ctx, &inventory.NewUserIdentityArgs{
		UserID:        loginUser.ID,
		Provider:      identity.Provider,
		Issuer:        identity.Issuer,
		Subject:       identity.Subject,
		Email:         identity.Email,
		EmailVerified: identity.EmailVerified,
		Name:          identity.Name,
		Avatar:        identity.Avatar,
	}); err != nil {
		_ = inventory.Rollback(tx)
		return nil, serializer.NewError(serializer.CodeDBError, "Failed to create identity", err)
	}

	if err := inventory.Commit(tx); err != nil {
		return nil, serializer.NewError(serializer.CodeDBError, "Failed to commit identity", err)
	}

	return userClient.GetByID(ctx, loginUser.ID)
}

func validateLoginUser(u *ent.User) error {
	if u.Status == user.StatusManualBanned || u.Status == user.StatusSysBanned {
		return serializer.NewError(serializer.CodeUserBaned, "This account has been blocked", nil)
	}
	if u.Status == user.StatusInactive {
		return serializer.NewError(serializer.CodeUserNotActivated, "This account is not activated", nil)
	}
	return nil
}
