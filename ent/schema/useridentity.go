package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// UserIdentity holds the schema definition for the UserIdentity entity.
type UserIdentity struct {
	ent.Schema
}

func (UserIdentity) Fields() []ent.Field {
	return []ent.Field{
		field.Int("user_id"),
		field.String("provider"),
		field.String("issuer"),
		field.String("subject"),
		field.String("email").
			Optional(),
		field.Bool("email_verified").
			Default(false),
		field.String("name").
			Optional(),
		field.String("avatar").
			Optional(),
	}
}

func (UserIdentity) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Field("user_id").
			Ref("identities").
			Unique().
			Required(),
	}
}

func (UserIdentity) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("issuer", "subject").Unique(),
		index.Fields("email"),
	}
}

func (UserIdentity) Mixin() []ent.Mixin {
	return []ent.Mixin{
		CommonMixin{},
	}
}
