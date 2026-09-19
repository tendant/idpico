package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"
	"github.com/tendant/idpico/internal/auth"
	"github.com/tendant/idpico/internal/crypto"
	"github.com/tendant/idpico/internal/domain"
	"github.com/tendant/idpico/internal/oidc"
	"github.com/tendant/idpico/internal/store"
)

// app holds what every command needs. Commands are plain methods so they can
// be tested against an in-memory store without exec'ing the binary.
type app struct {
	store store.Store
	keys  *crypto.KeyService
	out   io.Writer
}

var errUsage = errors.New(strings.TrimSpace(usage))

func (a *app) run(ctx context.Context, args []string) error {
	if len(args) < 2 {
		return errUsage
	}
	resource, cmd, rest := args[0], args[1], args[2:]
	switch resource {
	case "user":
		return a.user(ctx, cmd, rest)
	case "group":
		return a.group(ctx, cmd, rest)
	case "client":
		return a.client(ctx, cmd, rest)
	case "key":
		return a.key(ctx, cmd, rest)
	default:
		return fmt.Errorf("unknown resource %q\n\n%s", resource, strings.TrimSpace(usage))
	}
}

// Users

func (a *app) user(ctx context.Context, cmd string, args []string) error {
	users := a.store.Users()
	switch cmd {
	case "list":
		list, err := users.List(ctx)
		if err != nil {
			return err
		}
		tw := a.table()
		fmt.Fprintln(tw, "EMAIL\tNAME\tACTIVE\tVERIFIED\tADMIN\tID")
		for _, u := range list {
			fmt.Fprintf(tw, "%s\t%s\t%v\t%v\t%v\t%s\n", u.Email, u.DisplayName, u.Active, u.EmailVerified, u.Admin, u.ID)
		}
		return tw.Flush()

	case "add":
		fs := flag.NewFlagSet("user add", flag.ContinueOnError)
		name := fs.String("name", "", "display name")
		password := fs.String("password", "", "password (min 8 chars); omitted = random, printed once")
		admin := fs.Bool("admin", false, "grant admin UI access")
		verified := fs.Bool("verified", false, "mark email verified")
		inactive := fs.Bool("inactive", false, "create disabled")
		email, err := parseOne(fs, args, "email")
		if err != nil {
			return err
		}
		pw := *password
		generated := false
		if pw == "" {
			if pw, err = randomPassword(); err != nil {
				return err
			}
			generated = true
		}
		if err := auth.ValidatePassword(pw); err != nil {
			return err
		}
		hash, err := auth.HashPassword(pw)
		if err != nil {
			return err
		}
		u := &domain.User{
			ID: uuid.New().String(), Email: email, DisplayName: *name, PasswordHash: hash,
			Active: !*inactive, EmailVerified: *verified, Admin: *admin,
		}
		if err := users.Create(ctx, u); err != nil {
			return err
		}
		fmt.Fprintf(a.out, "created user %s (%s)\n", u.Email, u.ID)
		if generated {
			fmt.Fprintf(a.out, "password: %s\n", pw)
		}
		return nil

	case "passwd":
		if len(args) != 2 {
			return fmt.Errorf("usage: user passwd <email> <password>")
		}
		u, err := users.GetByEmail(ctx, args[0])
		if err != nil {
			return err
		}
		if err := auth.ValidatePassword(args[1]); err != nil {
			return err
		}
		hash, err := auth.HashPassword(args[1])
		if err != nil {
			return err
		}
		u.PasswordHash = hash
		if err := users.Update(ctx, u); err != nil {
			return err
		}
		_ = a.store.Sessions().DeleteByUserID(ctx, u.ID)
		_ = a.store.Tokens().RevokeByUserID(ctx, u.ID)
		fmt.Fprintf(a.out, "password updated for %s; sessions and refresh tokens revoked\n", u.Email)
		return nil

	case "set-admin":
		if len(args) != 2 || (args[1] != "true" && args[1] != "false") {
			return fmt.Errorf("usage: user set-admin <email> true|false")
		}
		u, err := users.GetByEmail(ctx, args[0])
		if err != nil {
			return err
		}
		u.Admin = args[1] == "true"
		if err := users.Update(ctx, u); err != nil {
			return err
		}
		fmt.Fprintf(a.out, "%s admin=%v\n", u.Email, u.Admin)
		return nil

	case "delete":
		if len(args) != 1 {
			return fmt.Errorf("usage: user delete <email>")
		}
		u, err := users.GetByEmail(ctx, args[0])
		if err != nil {
			return err
		}
		_ = a.store.Sessions().DeleteByUserID(ctx, u.ID)
		_ = a.store.Tokens().RevokeByUserID(ctx, u.ID)
		_ = a.store.Consents().DeleteByUserID(ctx, u.ID)
		_ = a.store.VerificationTokens().DeleteByUserID(ctx, u.ID, "")
		_ = a.store.Groups().RemoveUser(ctx, u.ID)
		if err := users.Delete(ctx, u.ID); err != nil {
			return err
		}
		fmt.Fprintf(a.out, "deleted user %s\n", u.Email)
		return nil
	}
	return fmt.Errorf("unknown user command %q", cmd)
}

// Groups

func (a *app) group(ctx context.Context, cmd string, args []string) error {
	groups := a.store.Groups()
	byName := func(name string) (*domain.Group, error) { return groups.GetByName(ctx, name) }

	switch cmd {
	case "list":
		list, err := groups.List(ctx)
		if err != nil {
			return err
		}
		tw := a.table()
		fmt.Fprintln(tw, "NAME\tMEMBERS\tDESCRIPTION")
		for _, g := range list {
			ids, _ := groups.MemberIDs(ctx, g.ID)
			fmt.Fprintf(tw, "%s\t%d\t%s\n", g.Name, len(ids), g.Description)
		}
		return tw.Flush()

	case "add":
		fs := flag.NewFlagSet("group add", flag.ContinueOnError)
		desc := fs.String("desc", "", "description")
		name, err := parseOne(fs, args, "name")
		if err != nil {
			return err
		}
		g := &domain.Group{ID: uuid.New().String(), Name: name, Description: *desc}
		if err := groups.Create(ctx, g); err != nil {
			return err
		}
		fmt.Fprintf(a.out, "created group %s\n", g.Name)
		return nil

	case "delete":
		if len(args) != 1 {
			return fmt.Errorf("usage: group delete <name>")
		}
		g, err := byName(args[0])
		if err != nil {
			return err
		}
		if err := groups.Delete(ctx, g.ID); err != nil {
			return err
		}
		fmt.Fprintf(a.out, "deleted group %s\n", g.Name)
		return nil

	case "members":
		if len(args) != 1 {
			return fmt.Errorf("usage: group members <name>")
		}
		g, err := byName(args[0])
		if err != nil {
			return err
		}
		ids, err := groups.MemberIDs(ctx, g.ID)
		if err != nil {
			return err
		}
		for _, id := range ids {
			if u, err := a.store.Users().GetByID(ctx, id); err == nil {
				fmt.Fprintln(a.out, u.Email)
			}
		}
		return nil

	case "add-member", "remove-member":
		if len(args) != 2 {
			return fmt.Errorf("usage: group %s <name> <email>", cmd)
		}
		g, err := byName(args[0])
		if err != nil {
			return err
		}
		u, err := a.store.Users().GetByEmail(ctx, args[1])
		if err != nil {
			return err
		}
		if cmd == "add-member" {
			if err := groups.AddMember(ctx, g.ID, u.ID); err != nil {
				return err
			}
			fmt.Fprintf(a.out, "added %s to %s\n", u.Email, g.Name)
		} else {
			if err := groups.RemoveMember(ctx, g.ID, u.ID); err != nil {
				return err
			}
			fmt.Fprintf(a.out, "removed %s from %s\n", u.Email, g.Name)
		}
		return nil
	}
	return fmt.Errorf("unknown group command %q", cmd)
}

// Clients

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func (a *app) client(ctx context.Context, cmd string, args []string) error {
	clients := a.store.Clients()
	switch cmd {
	case "list":
		list, err := clients.List(ctx)
		if err != nil {
			return err
		}
		tw := a.table()
		fmt.Fprintln(tw, "ID\tNAME\tTYPE\tCONSENT\tREDIRECT URIS")
		for _, c := range list {
			typ := "confidential"
			if c.Public {
				typ = "public"
			}
			consent := "required"
			if c.SkipConsent {
				consent = "skipped"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", c.ID, c.Name, typ, consent, strings.Join(c.RedirectURIs, " "))
		}
		return tw.Flush()

	case "add":
		fs := flag.NewFlagSet("client add", flag.ContinueOnError)
		var redirects multiFlag
		fs.Var(&redirects, "redirect", "redirect URI (repeatable)")
		name := fs.String("name", "", "display name (default: id)")
		public := fs.Bool("public", false, "public client (PKCE, no secret)")
		skipConsent := fs.Bool("skip-consent", false, "first-party: skip the consent screen")
		scopes := fs.String("scopes", "openid profile email offline_access groups", "allowed scopes")
		accessTTL := fs.Duration("access-ttl", 0, "access/ID token lifetime (e.g. 5m); 0 = server default")
		refreshTTL := fs.Duration("refresh-ttl", 0, "refresh token lifetime (e.g. 720h); 0 = server default")
		id, err := parseOne(fs, args, "id")
		if err != nil {
			return err
		}
		if len(redirects) == 0 {
			return fmt.Errorf("at least one -redirect URI is required")
		}
		c := &domain.Client{
			ID: id, Name: *name, RedirectURIs: redirects, Public: *public, SkipConsent: *skipConsent,
			Scopes:          strings.Fields(*scopes),
			GrantTypes:      []string{"authorization_code", "refresh_token"},
			AccessTokenTTL:  *accessTTL,
			RefreshTokenTTL: *refreshTTL,
		}
		if c.Name == "" {
			c.Name = id
		}
		var secret string
		if !c.Public {
			if secret, err = randomPassword(); err != nil {
				return err
			}
			if c.Secret, err = oidc.HashClientSecret(secret); err != nil {
				return err
			}
		}
		if err := clients.Create(ctx, c); err != nil {
			return err
		}
		fmt.Fprintf(a.out, "created client %s\n", c.ID)
		if secret != "" {
			fmt.Fprintf(a.out, "client_secret: %s\n", secret)
		}
		return nil

	case "reset-secret":
		if len(args) != 1 {
			return fmt.Errorf("usage: client reset-secret <id>")
		}
		c, err := clients.GetByID(ctx, args[0])
		if err != nil {
			return err
		}
		if c.Public {
			return fmt.Errorf("client %s is public and has no secret", c.ID)
		}
		secret, err := randomPassword()
		if err != nil {
			return err
		}
		if c.Secret, err = oidc.HashClientSecret(secret); err != nil {
			return err
		}
		if err := clients.Update(ctx, c); err != nil {
			return err
		}
		fmt.Fprintf(a.out, "client_secret: %s\n", secret)
		return nil

	case "delete":
		if len(args) != 1 {
			return fmt.Errorf("usage: client delete <id>")
		}
		_ = a.store.Tokens().RevokeByClientID(ctx, args[0])
		if err := clients.Delete(ctx, args[0]); err != nil {
			return err
		}
		fmt.Fprintf(a.out, "deleted client %s\n", args[0])
		return nil
	}
	return fmt.Errorf("unknown client command %q", cmd)
}

// Keys

func (a *app) key(ctx context.Context, cmd string, args []string) error {
	switch cmd {
	case "list":
		keys, err := a.keys.ListKeys(ctx)
		if err != nil {
			return err
		}
		tw := a.table()
		fmt.Fprintln(tw, "KID\tALG\tACTIVE\tCREATED\tEXPIRES")
		for _, k := range keys {
			exp := "-"
			if !k.ExpiresAt.IsZero() {
				exp = k.ExpiresAt.Format(time.RFC3339)
			}
			fmt.Fprintf(tw, "%s\t%s\t%v\t%s\t%s\n", k.Kid, k.Alg, k.Active, k.CreatedAt.Format(time.RFC3339), exp)
		}
		return tw.Flush()

	case "rotate":
		fs := flag.NewFlagSet("key rotate", flag.ContinueOnError)
		grace := fs.Duration("grace", 24*time.Hour, "how long the previous key keeps verifying tokens")
		if err := fs.Parse(args); err != nil {
			return err
		}
		if _, err := a.keys.EnsureActiveKey(ctx); err != nil {
			return err
		}
		k, err := a.keys.RotateKey(ctx, *grace)
		if err != nil {
			return err
		}
		fmt.Fprintf(a.out, "active key is now %s (previous key valid for %s)\n", k.Kid, grace)
		return nil
	}
	return fmt.Errorf("unknown key command %q", cmd)
}

// Helpers

// parseOne parses flags that may appear before or after a single positional
// argument, e.g. "user add alice@x.com -admin" or "user add -admin alice@x.com".
func parseOne(fs *flag.FlagSet, args []string, what string) (string, error) {
	var positional []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return "", err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			break
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
	if len(positional) != 1 {
		return "", fmt.Errorf("expected exactly one %s argument", what)
	}
	return positional[0], nil
}

func (a *app) table() *tabwriter.Writer {
	return tabwriter.NewWriter(a.out, 0, 4, 2, ' ', 0)
}

func randomPassword() (string, error) {
	kp, err := crypto.RandomToken(24)
	if err != nil {
		return "", err
	}
	return kp, nil
}
