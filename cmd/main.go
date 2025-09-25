package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/hydazz/crowdsec-cilium-bouncer/internal/bouncer"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cfg, err := bouncer.LoadConfigFromEnv()
	if err != nil {
		logger.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	restConfig, err := rest.InClusterConfig()
	if err != nil {
		logger.Error("failed to load in-cluster config", "error", err)
		os.Exit(1)
	}

	scheme := runtime.NewScheme()
	kubeClient, err := client.New(restConfig, client.Options{Scheme: scheme})
	if err != nil {
		logger.Error("failed to create kubernetes client", "error", err)
		os.Exit(1)
	}

	runner, err := bouncer.NewRunner(cfg, kubeClient, logger)
	if err != nil {
		logger.Error("failed to initialise runner", "error", err)
		os.Exit(1)
	}

	if err := runner.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("bouncer exited with error", "error", err)
		os.Exit(1)
	}
}
