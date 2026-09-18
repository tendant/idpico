package oidc

import (
	"context"
	"fmt"
	"strings"

	"github.com/tendant/simple-idp/internal/crypto"
	"github.com/tendant/simple-idp/internal/domain"
	"github.com/tendant/simple-idp/internal/store"
)

// ScopeGroups is the scope that releases group memberships to a client.
const ScopeGroups = "groups"

// DefaultGroupsClaim is the claim name group memberships are emitted under.
const DefaultGroupsClaim = "groups"

// GroupClaims adds a user's group memberships to tokens and userinfo when
// the groups scope has been granted.
type GroupClaims struct {
	groups    store.GroupRepository
	claimName string
}

// NewGroupClaims creates a GroupClaims emitting memberships under claimName
// (empty means "groups").
func NewGroupClaims(groups store.GroupRepository, claimName string) *GroupClaims {
	if claimName == "" {
		claimName = DefaultGroupsClaim
	}
	return &GroupClaims{groups: groups, claimName: claimName}
}

// ClaimName returns the claim the memberships are emitted under.
func (g *GroupClaims) ClaimName() string { return g.claimName }

// Names returns the user's group names, sorted.
func (g *GroupClaims) Names(ctx context.Context, userID string) ([]string, error) {
	groups, err := g.groups.GroupsForUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to load groups: %w", err)
	}
	names := make([]string, 0, len(groups))
	for _, grp := range groups {
		names = append(names, grp.Name)
	}
	return names, nil
}

// Apply adds the groups claim to claims when scope includes groups. A user
// with no memberships gets an empty list so clients can tell "none" from
// "not released".
func (g *GroupClaims) Apply(ctx context.Context, user *domain.User, scope string, claims *crypto.Claims) error {
	if g == nil || !hasScope(scope, ScopeGroups) {
		return nil
	}
	names, err := g.Names(ctx, user.ID)
	if err != nil {
		return err
	}
	if g.claimName == DefaultGroupsClaim {
		claims.Groups = names
	} else {
		claims.SetExtra(g.claimName, names)
	}
	return nil
}

func hasScope(scope, want string) bool {
	for _, s := range strings.Fields(scope) {
		if s == want {
			return true
		}
	}
	return false
}
