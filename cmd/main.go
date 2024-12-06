package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"

	"auth/internal/config"
	"auth/internal/database/postgresql"
	"auth/internal/email/mockmail"
	"auth/internal/http/handlers/get"
	"auth/internal/http/handlers/refresh"
	"auth/internal/lib/logger/sl"
)

const (
	envDev  = "Development"
	envProd = "Production"
)

func main() {
	configPath := os.Getenv("CONFIG_PATH")
	cfg := config.MustLoad(configPath)

	log := setupLogger(cfg.Env)
	log = log.With(slog.String("env", cfg.Env))

	log.Info("Starting server", slog.String("Address",
		cfg.Server.Host+":"+strconv.Itoa(cfg.Server.Port)))
	log.Debug("Logger debug mode enabled")

	database, err := postgresql.New(cfg.Database)
	if err != nil {
		log.Error("Failed to initialize database", sl.Err(err))
	}

	mailer := mockmail.New(cfg.Email, log)

	router := chi.NewRouter()

	router.Use(middleware.RequestID)
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)
	router.Use(middleware.URLFormat)

	router.Get("/{user_guid}", get.New(log, database, cfg.JWT))
	router.Post("/", refresh.New(log, database, mailer, cfg.JWT))

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	srv := &http.Server{
		Addr:         cfg.Server.Host + ":" + strconv.Itoa(cfg.Server.Port),
		Handler:      router,
		ReadTimeout:  cfg.HTTP.Timeout,
		WriteTimeout: cfg.HTTP.Timeout,
		IdleTimeout:  cfg.HTTP.IdleTimeout,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil {
			log.Error("Runing error", sl.Err(err))
		}
	}()

	log.Info("Server started")

	<-done
	log.Info("Stopping server")

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Server.Timeout)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Error("Failed to stop server", sl.Err(err))
		return
	}

	log.Info("Server stopped")
}

func setupLogger(env string) *slog.Logger {
	var log *slog.Logger

	switch env {
	case envDev:
		log = slog.New(slog.NewJSONHandler(os.Stdout,
			&slog.HandlerOptions{Level: slog.LevelDebug}))
	case envProd:
		log = slog.New(slog.NewJSONHandler(os.Stdout,
			&slog.HandlerOptions{Level: slog.LevelInfo}))
	}

	return log
}
