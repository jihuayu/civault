package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"civault/internal/vault"
	"civault/web"
)

func main() {
	if e := run(); e != nil {
		slog.New(slog.NewJSONHandler(os.Stderr, nil)).Error("server stopped", "reason", e.Error())
		os.Exit(1)
	}
}

func run() error {
	data := flag.String("data-dir", "/data", "persistent data directory")
	listen := flag.String("listen", ":8080", "listen address")
	backup := flag.String("backup", "", "create a consistent SQLite backup at a new path and exit")
	flag.Parse()
	a, e := vault.Open(*data, os.Getenv("CIVAULT_MASTER_KEY"), web.Assets(), os.Stdout)
	if e != nil {
		return e
	}
	defer a.Close()
	if *backup != "" {
		if e = a.Backup(context.Background(), *backup); e != nil {
			return fmt.Errorf("backup failed: %w", e)
		}
		return nil
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	workerDone := make(chan struct{})
	go func() { defer close(workerDone); a.RunWorker(ctx) }()
	srv := &http.Server{Addr: *listen, Handler: a.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(c)
	}()
	if e = srv.ListenAndServe(); e != nil && e != http.ErrServerClosed {
		stop()
		<-workerDone
		return fmt.Errorf("HTTP server failed: %w", e)
	}
	stop()
	<-workerDone
	return nil
}
