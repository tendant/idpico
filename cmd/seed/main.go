// Package main provides a utility to seed test data for development.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/google/uuid"
	"github.com/tendant/simple-idp/internal/auth"
	"github.com/tendant/simple-idp/internal/domain"
	"github.com/tendant/simple-idp/internal/store/file"
)

func main() {
	dataDir := flag.String("data-dir", "./data", "Data directory")
	flag.Parse()

	// Initialize store
	store, err := file.NewStore(*dataDir)
	if err != nil {
		log.Fatalf("Failed to initialize store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	// Create test client
	client := &domain.Client{
		ID:           "test-client",
		Secret:       "test-secret",
		Name:         "Test Application",
		RedirectURIs: []string{"http://localhost:3000/callback", "http://localhost:8081/callback"},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		Scopes:       []string{"openid", "profile", "email", "offline_access"},
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
		Scopes:       []string{"openid", "profile", "email", "offline_access"},
		Public:       true,
	}

	if err := store.Clients().Create(ctx, publicClient); err != nil {
		fmt.Printf("Public client may already exist: %v\n", err)
	} else {
		fmt.Printf("Created public client: %s\n", publicClient.ID)
	}

	// Create test user
	password := "password123"
	hash, err := auth.HashPassword(password)
	if err != nil {
		log.Fatalf("Failed to hash password: %v", err)
	}

	user := &domain.User{
		ID:           uuid.New().String(),
		Email:        "test@example.com",
		PasswordHash: hash,
		DisplayName:  "Test User",
		Active:       true,
	}

	if err := store.Users().Create(ctx, user); err != nil {
		fmt.Printf("User may already exist: %v\n", err)
	} else {
		fmt.Printf("Created user: %s (password: %s)\n", user.Email, password)
	}

	fmt.Println("\nSeed data created successfully!")
	fmt.Println("\nTest with:")
	fmt.Println("  1. Start server: IDP_COOKIE_SECRET=your-secret-here go run ./cmd/idp")
	fmt.Println("  2. Open browser: http://localhost:8080/authorize?client_id=test-client&redirect_uri=http://localhost:3000/callback&response_type=code&scope=openid%20profile%20email&state=test123")
	fmt.Println("  3. Login with: test@example.com / password123")

	os.Exit(0)
}
