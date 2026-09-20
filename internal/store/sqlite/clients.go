package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/tendant/idpico/internal/domain"
	idperrors "github.com/tendant/idpico/internal/errors"
)

type clientRepository struct {
	db *sql.DB
}

const clientColumns = "id, secret, name, redirect_uris, grant_types, scopes, public, skip_consent, minimal_id_token, access_token_ttl, refresh_token_ttl, created_at, updated_at"

// String slices on Client are stored as JSON arrays; nobody queries by element.

func marshalStrings(v []string) (string, error) {
	if v == nil {
		v = []string{}
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func unmarshalStrings(s string) ([]string, error) {
	if s == "" {
		return []string{}, nil
	}
	var v []string
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return nil, err
	}
	if v == nil {
		v = []string{}
	}
	return v, nil
}

func scanClient(row interface{ Scan(...any) error }) (*domain.Client, error) {
	var (
		c                                domain.Client
		redirectURIs, grantTypes, scopes string
		accessTTL, refreshTTL            int64 // seconds
	)
	if err := row.Scan(&c.ID, &c.Secret, &c.Name, &redirectURIs, &grantTypes, &scopes, &c.Public, &c.SkipConsent, &c.MinimalIDToken, &accessTTL, &refreshTTL, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return nil, err
	}
	c.AccessTokenTTL = time.Duration(accessTTL) * time.Second
	c.RefreshTokenTTL = time.Duration(refreshTTL) * time.Second

	var err error
	if c.RedirectURIs, err = unmarshalStrings(redirectURIs); err != nil {
		return nil, err
	}
	if c.GrantTypes, err = unmarshalStrings(grantTypes); err != nil {
		return nil, err
	}
	if c.Scopes, err = unmarshalStrings(scopes); err != nil {
		return nil, err
	}
	return &c, nil
}

func (r *clientRepository) Create(ctx context.Context, client *domain.Client) error {
	redirectURIs, grantTypes, scopes, err := encodeClientLists(client)
	if err != nil {
		return idperrors.Internal("failed to encode client", err)
	}

	now := time.Now()
	client.CreatedAt = now
	client.UpdatedAt = now

	_, err = r.db.ExecContext(ctx,
		`INSERT INTO clients (`+clientColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		client.ID, client.Secret, client.Name, redirectURIs, grantTypes, scopes, client.Public, client.SkipConsent, client.MinimalIDToken,
		int64(client.AccessTokenTTL/time.Second), int64(client.RefreshTokenTTL/time.Second), utc(client.CreatedAt), utc(client.UpdatedAt),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return idperrors.AlreadyExists("client", client.ID)
		}
		return idperrors.Internal("failed to create client", err)
	}
	return nil
}

func encodeClientLists(client *domain.Client) (redirectURIs, grantTypes, scopes string, err error) {
	if redirectURIs, err = marshalStrings(client.RedirectURIs); err != nil {
		return
	}
	if grantTypes, err = marshalStrings(client.GrantTypes); err != nil {
		return
	}
	scopes, err = marshalStrings(client.Scopes)
	return
}

func (r *clientRepository) GetByID(ctx context.Context, id string) (*domain.Client, error) {
	c, err := scanClient(r.db.QueryRowContext(ctx, `SELECT `+clientColumns+` FROM clients WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, idperrors.NotFound("client", id)
	}
	if err != nil {
		return nil, idperrors.Internal("failed to load client", err)
	}
	return c, nil
}

func (r *clientRepository) Update(ctx context.Context, client *domain.Client) error {
	redirectURIs, grantTypes, scopes, err := encodeClientLists(client)
	if err != nil {
		return idperrors.Internal("failed to encode client", err)
	}

	client.UpdatedAt = time.Now()

	res, err := r.db.ExecContext(ctx,
		`UPDATE clients SET secret = ?, name = ?, redirect_uris = ?, grant_types = ?, scopes = ?, public = ?, skip_consent = ?, minimal_id_token = ?, access_token_ttl = ?, refresh_token_ttl = ?, updated_at = ? WHERE id = ?`,
		client.Secret, client.Name, redirectURIs, grantTypes, scopes, client.Public, client.SkipConsent, client.MinimalIDToken,
		int64(client.AccessTokenTTL/time.Second), int64(client.RefreshTokenTTL/time.Second), utc(client.UpdatedAt), client.ID,
	)
	if err != nil {
		return idperrors.Internal("failed to update client", err)
	}
	ok, err := rowsAffected(res)
	if err != nil {
		return idperrors.Internal("failed to update client", err)
	}
	if !ok {
		return idperrors.NotFound("client", client.ID)
	}
	return nil
}

func (r *clientRepository) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM clients WHERE id = ?`, id)
	if err != nil {
		return idperrors.Internal("failed to delete client", err)
	}
	ok, err := rowsAffected(res)
	if err != nil {
		return idperrors.Internal("failed to delete client", err)
	}
	if !ok {
		return idperrors.NotFound("client", id)
	}
	return nil
}

func (r *clientRepository) List(ctx context.Context) ([]*domain.Client, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+clientColumns+` FROM clients ORDER BY created_at, id`)
	if err != nil {
		return nil, idperrors.Internal("failed to list clients", err)
	}
	defer rows.Close()

	clients := []*domain.Client{}
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, idperrors.Internal("failed to scan client", err)
		}
		clients = append(clients, c)
	}
	if err := rows.Err(); err != nil {
		return nil, idperrors.Internal("failed to list clients", err)
	}
	return clients, nil
}
