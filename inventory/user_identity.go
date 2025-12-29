package inventory

import (
	"context"
	"fmt"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/useridentity"
)

type (
	UserIdentityClient interface {
		TxOperator
		GetByIssuerSubject(ctx context.Context, issuer, subject string) (*ent.UserIdentity, error)
		Create(ctx context.Context, args *NewUserIdentityArgs) (*ent.UserIdentity, error)
		Update(ctx context.Context, identity *ent.UserIdentity, args *UpdateUserIdentityArgs) (*ent.UserIdentity, error)
	}

	NewUserIdentityArgs struct {
		UserID        int
		Provider      string
		Issuer        string
		Subject       string
		Email         string
		EmailVerified bool
		Name          string
		Avatar        string
	}

	UpdateUserIdentityArgs struct {
		Email         *string
		EmailVerified *bool
		Name          *string
		Avatar        *string
	}
)

func NewUserIdentityClient(client *ent.Client) UserIdentityClient {
	return &userIdentityClient{client: client}
}

type userIdentityClient struct {
	client *ent.Client
}

func (c *userIdentityClient) SetClient(newClient *ent.Client) TxOperator {
	return &userIdentityClient{client: newClient}
}

func (c *userIdentityClient) GetClient() *ent.Client {
	return c.client
}

func (c *userIdentityClient) GetByIssuerSubject(ctx context.Context, issuer, subject string) (*ent.UserIdentity, error) {
	return c.client.UserIdentity.Query().
		Where(useridentity.Issuer(issuer), useridentity.Subject(subject)).
		First(ctx)
}

func (c *userIdentityClient) Create(ctx context.Context, args *NewUserIdentityArgs) (*ent.UserIdentity, error) {
	if args == nil {
		return nil, fmt.Errorf("identity args are required")
	}

	query := c.client.UserIdentity.Create().
		SetUserID(args.UserID).
		SetProvider(args.Provider).
		SetIssuer(args.Issuer).
		SetSubject(args.Subject).
		SetEmailVerified(args.EmailVerified)

	if args.Email != "" {
		query.SetEmail(args.Email)
	}
	if args.Name != "" {
		query.SetName(args.Name)
	}
	if args.Avatar != "" {
		query.SetAvatar(args.Avatar)
	}

	return query.Save(ctx)
}

func (c *userIdentityClient) Update(ctx context.Context, identity *ent.UserIdentity, args *UpdateUserIdentityArgs) (*ent.UserIdentity, error) {
	if identity == nil {
		return nil, fmt.Errorf("identity is required")
	}
	if args == nil {
		return identity, nil
	}

	query := identity.Update()
	if args.Email != nil {
		if *args.Email == "" {
			query.ClearEmail()
		} else {
			query.SetEmail(*args.Email)
		}
	}
	if args.EmailVerified != nil {
		query.SetEmailVerified(*args.EmailVerified)
	}
	if args.Name != nil {
		if *args.Name == "" {
			query.ClearName()
		} else {
			query.SetName(*args.Name)
		}
	}
	if args.Avatar != nil {
		if *args.Avatar == "" {
			query.ClearAvatar()
		} else {
			query.SetAvatar(*args.Avatar)
		}
	}

	return query.Save(ctx)
}
