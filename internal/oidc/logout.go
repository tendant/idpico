package oidc

import (
	"context"
	"net/url"

	"github.com/tendant/idpico/internal/domain"
	idperrors "github.com/tendant/idpico/internal/errors"
)

// PostLogoutRedirect resolves an RP-Initiated Logout 1.0 request to the URI
// the user agent is sent back to, with state appended (§3). The relying
// party is named by id_token_hint (its aud) or client_id, or both, which
// must then agree (§2); redirectURI must exactly match one of that client's
// registered redirect URIs. IDPico has no separate post_logout_redirect_uris
// registration: a client may return the user to any of its redirect URIs.
func (s *TokenService) PostLogoutRedirect(ctx context.Context, idTokenHint, clientID, redirectURI, state string) (string, error) {
	if idTokenHint != "" {
		claims, err := s.tokenGenerator.ParseIDTokenHint(ctx, idTokenHint)
		if err != nil {
			return "", idperrors.InvalidInput("invalid id_token_hint")
		}
		if len(claims.Audience) != 1 {
			return "", idperrors.InvalidInput("id_token_hint must have a single audience")
		}
		if clientID != "" && clientID != claims.Audience[0] {
			return "", idperrors.InvalidInput("client_id does not match id_token_hint")
		}
		clientID = claims.Audience[0]
	}
	if clientID == "" {
		return "", idperrors.InvalidInput("post_logout_redirect_uri requires id_token_hint or client_id")
	}

	client, err := s.clients.GetByID(ctx, clientID)
	if err != nil {
		return "", idperrors.InvalidInput("unknown client")
	}
	if !registeredRedirect(client, redirectURI) {
		return "", idperrors.InvalidInput("post_logout_redirect_uri is not registered for the client")
	}

	u, err := url.Parse(redirectURI)
	if err != nil {
		return "", idperrors.InvalidInput("invalid post_logout_redirect_uri")
	}
	if state != "" {
		q := u.Query()
		q.Set("state", state)
		u.RawQuery = q.Encode()
	}
	return u.String(), nil
}

func registeredRedirect(client *domain.Client, uri string) bool {
	for _, r := range client.RedirectURIs {
		if r == uri {
			return true
		}
	}
	return false
}
