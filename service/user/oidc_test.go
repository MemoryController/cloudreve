package user

import (
	"context"
	"testing"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/enttest"
	"github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
	"github.com/cloudreve/Cloudreve/v4/pkg/oidc"
	"github.com/stretchr/testify/require"
)

func TestResolveOIDCUserExistingIdentity(t *testing.T) {
	ctx := context.Background()
	client := enttest.Open(t, "sqlite3", "file:oidc?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() { client.Close() })

	groupID := createTestGroup(t, ctx, client)
	userClient := inventory.NewUserClient(client)
	identityClient := inventory.NewUserIdentityClient(client)

	createdUser, err := userClient.Create(ctx, &inventory.NewUserArgs{
		Email:   "existing@example.com",
		Status:  user.StatusActive,
		GroupID: groupID,
	})
	require.NoError(t, err)

	_, err = identityClient.Create(ctx, &inventory.NewUserIdentityArgs{
		UserID:        createdUser.ID,
		Provider:      "demo",
		Issuer:        "https://issuer.example.com",
		Subject:       "sub-1",
		Email:         "existing@example.com",
		EmailVerified: true,
	})
	require.NoError(t, err)

	resolved, err := resolveOIDCUser(ctx, userClient, identityClient, oidc.ProviderConfig{
		AllowEmailLink: true,
		AutoCreateUser: true,
	}, oidc.Identity{
		Provider:      "demo",
		Issuer:        "https://issuer.example.com",
		Subject:       "sub-1",
		Email:         "existing@example.com",
		EmailVerified: true,
	}, groupID)
	require.NoError(t, err)
	require.Equal(t, createdUser.ID, resolved.ID)
}

func TestResolveOIDCUserEmailLink(t *testing.T) {
	ctx := context.Background()
	client := enttest.Open(t, "sqlite3", "file:oidc2?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() { client.Close() })

	groupID := createTestGroup(t, ctx, client)
	userClient := inventory.NewUserClient(client)
	identityClient := inventory.NewUserIdentityClient(client)

	createdUser, err := userClient.Create(ctx, &inventory.NewUserArgs{
		Email:   "linked@example.com",
		Status:  user.StatusActive,
		GroupID: groupID,
	})
	require.NoError(t, err)

	resolved, err := resolveOIDCUser(ctx, userClient, identityClient, oidc.ProviderConfig{
		AllowEmailLink: true,
	}, oidc.Identity{
		Provider:      "demo",
		Issuer:        "https://issuer.example.com",
		Subject:       "sub-2",
		Email:         "linked@example.com",
		EmailVerified: true,
	}, groupID)
	require.NoError(t, err)
	require.Equal(t, createdUser.ID, resolved.ID)

	identity, err := identityClient.GetByIssuerSubject(ctx, "https://issuer.example.com", "sub-2")
	require.NoError(t, err)
	require.Equal(t, createdUser.ID, identity.UserID)
}

func TestResolveOIDCUserAutoCreate(t *testing.T) {
	ctx := context.Background()
	client := enttest.Open(t, "sqlite3", "file:oidc3?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() { client.Close() })

	groupID := createTestGroup(t, ctx, client)
	userClient := inventory.NewUserClient(client)
	identityClient := inventory.NewUserIdentityClient(client)

	resolved, err := resolveOIDCUser(ctx, userClient, identityClient, oidc.ProviderConfig{
		AutoCreateUser: true,
	}, oidc.Identity{
		Provider:      "demo",
		Issuer:        "https://issuer.example.com",
		Subject:       "sub-3",
		Email:         "new@example.com",
		EmailVerified: true,
		Name:          "New User",
	}, groupID)
	require.NoError(t, err)
	require.Equal(t, "new@example.com", resolved.Email)
}

func TestResolveOIDCUserRejectsUnverifiedEmail(t *testing.T) {
	ctx := context.Background()
	client := enttest.Open(t, "sqlite3", "file:oidc4?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() { client.Close() })

	groupID := createTestGroup(t, ctx, client)
	userClient := inventory.NewUserClient(client)
	identityClient := inventory.NewUserIdentityClient(client)

	_, err := resolveOIDCUser(ctx, userClient, identityClient, oidc.ProviderConfig{
		AutoCreateUser: true,
	}, oidc.Identity{
		Provider:      "demo",
		Issuer:        "https://issuer.example.com",
		Subject:       "sub-4",
		Email:         "new@example.com",
		EmailVerified: false,
	}, groupID)
	require.Error(t, err)
}

func createTestGroup(t *testing.T, ctx context.Context, client *ent.Client) int {
	t.Helper()
	perms := &boolset.BooleanSet{}
	group, err := client.Group.Create().
		SetName("default").
		SetPermissions(perms).
		Save(ctx)
	require.NoError(t, err)
	return group.ID
}
