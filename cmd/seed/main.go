// Package main provides a utility to seed test data for development.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/tendant/idpico/internal/auth"
	"github.com/tendant/idpico/internal/domain"
	"github.com/tendant/idpico/internal/oidc"
	"github.com/tendant/idpico/internal/store"
	"github.com/tendant/idpico/internal/store/file"
	"github.com/tendant/idpico/internal/store/sqlite"
)

func main() {
	driver := flag.String("driver", "sqlite", "Store driver: sqlite or file")
	dataDir := flag.String("data-dir", "./data", "Data directory")
	dsn := flag.String("dsn", "", "SQLite database path (default: <data-dir>/idpico.db)")
	flag.Parse()

	ctx := context.Background()

	// Initialize store
	var (
		store store.Store
		err   error
	)
	switch *driver {
	case "sqlite":
		path := *dsn
		if path == "" {
			path = filepath.Join(*dataDir, "idpico.db")
		}
		store, err = sqlite.NewStore(ctx, path)
	case "file":
		store, err = file.NewStore(*dataDir)
	default:
		log.Fatalf("Unknown driver %q (expected sqlite or file)", *driver)
	}
	if err != nil {
		log.Fatalf("Failed to initialize store: %v", err)
	}
	defer store.Close()

	// Create test client (secret: test-secret)
	secretHash, err := oidc.HashClientSecret("test-secret")
	if err != nil {
		log.Fatalf("Failed to hash client secret: %v", err)
	}
	client := &domain.Client{
		ID:           "test-client",
		Secret:       secretHash,
		Name:         "Test Application",
		RedirectURIs: []string{"http://localhost:3000/callback", "http://localhost:8081/callback"},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		Scopes:       []string{"openid", "profile", "email", "offline_access", "groups"},
		Public:       false,
	}

	if err := store.Clients().Create(ctx, client); err != nil {
		fmt.Printf("Client may already exist: %v\n", err)
	} else {
		fmt.Printf("Created client: %s\n", client.ID)
	}

	// Create public test client (PKCE required)
	publicClient := &domain.Client{
		ID:           "test-public-client",
		Name:         "Test Public Application",
		RedirectURIs: []string{"http://localhost:3000/callback", "http://localhost:8081/callback"},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		Scopes:       []string{"openid", "profile", "email", "offline_access", "groups"},
		Public:       true,
	}

	if err := store.Clients().Create(ctx, publicClient); err != nil {
		fmt.Printf("Public client may already exist: %v\n", err)
	} else {
		fmt.Printf("Created public client: %s\n", publicClient.ID)
	}

	// Create test users: an admin and a regular user
	password := "password123"
	hash, err := auth.HashPassword(password)
	if err != nil {
		log.Fatalf("Failed to hash password: %v", err)
	}

	users := []*domain.User{
		{ID: uuid.New().String(), Email: "test@example.com", PasswordHash: hash, DisplayName: "Test User", Active: true, EmailVerified: true, Admin: true},
		{ID: uuid.New().String(), Email: "alice@example.com", PasswordHash: hash, DisplayName: "Alice", Active: true, EmailVerified: true},
	}
	for _, u := range users {
		if err := store.Users().Create(ctx, u); err != nil {
			fmt.Printf("User %s may already exist: %v\n", u.Email, err)
		} else {
			fmt.Printf("Created user: %s (password: %s, admin: %v)\n", u.Email, password, u.Admin)
		}
	}

	// Create groups and memberships (released in the "groups" claim)
	groups := []struct {
		name, description string
		members           []string
	}{
		{"admins", "Administrators", []string{"test@example.com"}},
		{"devs", "Developers", []string{"test@example.com", "alice@example.com"}},
	}
	for _, g := range groups {
		group, err := store.Groups().GetByName(ctx, g.name)
		if err != nil {
			group = &domain.Group{ID: uuid.New().String(), Name: g.name, Description: g.description}
			if err := store.Groups().Create(ctx, group); err != nil {
				fmt.Printf("Group %s could not be created: %v\n", g.name, err)
				continue
			}
			fmt.Printf("Created group: %s\n", g.name)
		}
		for _, email := range g.members {
			u, err := store.Users().GetByEmail(ctx, email)
			if err != nil {
				continue
			}
			if err := store.Groups().AddMember(ctx, group.ID, u.ID); err != nil {
				fmt.Printf("Could not add %s to %s: %v\n", email, g.name, err)
			}
		}
		fmt.Printf("Group %s members: %s\n", g.name, strings.Join(g.members, ", "))
	}

	fmt.Println("\nSeed data created successfully!")
	fmt.Println("\nTest with:")
	fmt.Println("  1. Start server: IDPICO_COOKIE_SECRET=your-secret-here go run ./cmd/idpico")
	fmt.Println("  2. Open browser: http://localhost:8080/authorize?client_id=test-client&redirect_uri=http://localhost:3000/callback&response_type=code&scope=openid%20profile%20email&state=test123")
	fmt.Println("  3. Login with: test@example.com / password123 (admin, groups: admins devs)")
	fmt.Println("                 alice@example.com / password123 (groups: devs)")
	fmt.Println("  4. Or use the playground: http://localhost:8080/playground and the admin UI: http://localhost:8080/admin")

	os.Exit(0)
}
