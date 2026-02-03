// Package main is the entry point for the simple-idp Identity Provider.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tendant/simple-idp/internal/config"
	idphttp "github.com/tendant/simple-idp/internal/http"
	"github.com/tendant/simple-idp/internal/store/file"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	// Setup logger
	var handler slog.Handler
	if cfg.LogFormat == "json" {
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: parseLogLevel(cfg.LogLevel),
		})
	} else {
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: parseLogLevel(cfg.LogLevel),
		})
	}
	logger := slog.New(handler)
	slog.SetDefault(logger)

	// Initialize file store
	store, err := file.NewStore(cfg.DataDir)
	if err != nil {
		logger.Error("failed to initialize store", "error", err)
		os.Exit(1)
	}
	defer store.Close()

	logger.Info("initialized file store", "data_dir", cfg.DataDir)

	// Create HTTP server
	server := idphttp.NewServer(cfg.Addr(), idphttp.WithLogger(logger))

	// Start server in goroutine
	go func() {
		if err := server.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	logger.Info("server started", "addr", cfg.Addr(), "issuer", cfg.IssuerURL)

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("shutting down server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Error("server forced to shutdown", "error", err)
		os.Exit(1)
	}

	logger.Info("server stopped")
}

func parseLogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
