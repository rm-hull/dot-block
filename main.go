package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/earthboundkid/versioninfo/v2"
	"github.com/rm-hull/dot-block/internal"
	"github.com/rm-hull/dot-block/internal/config"
	"github.com/rm-hull/dot-block/internal/logging"
	"github.com/spf13/cobra"
)

func parseLogLevel(level string) slog.Level {
	switch strings.ToUpper(level) {
	case "DEBUG":
		return slog.LevelDebug
	case "INFO":
		return slog.LevelInfo
	case "WARN":
		return slog.LevelWarn
	case "ERROR":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func main() {
	var logLevelVar slog.LevelVar

	handler := logging.NewSentryHandler(
		slog.LevelError,
		logging.NewTracingHandler(
			slog.NewJSONHandler(
				os.Stderr,
				&slog.HandlerOptions{
					Level:       &logLevelVar,
					AddSource:   true,
					ReplaceAttr: logging.ReplaceAttr})),
	)

	app := internal.App{Logger: slog.New(handler)}
	logging.BridgeStandardLog(handler)

	var configPath string
	var showVersion bool

	rootCmd := &cobra.Command{
		Use:   "dot-block",
		Short: "Secure DNS-over-TLS forwarder with ad/tracker blocking",
		Long:  "dot-block is a secure DNS-over-TLS (DoT) server that acts as a DNS forwarder with built-in ad and tracker blocking. It supports customizable blocklists, cache management, and can be integrated with ACME for automatic TLS certificate management.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if showVersion {
				fmt.Println(versioninfo.Short())
				os.Exit(0)
			}

			cfg, err := config.Load(configPath)
			if err != nil {
				app.Logger.Error("Failed to load configuration", "error", err)
				os.Exit(1)
			}

			config.ApplyEnvOverrides(cfg)
			app.Config = cfg

			logLevelVar.Set(parseLogLevel(string(cfg.Server.LogLevel)))

			if cfg.Server.DevMode {
				if cfg.Server.DnsPort == 0 {
					cfg.Server.DnsPort = 8053
				}
				if cfg.Server.DotPort == 0 {
					cfg.Server.DotPort = 8853
				}
				app.Logger.Warn("Running in DEV MODE: TLS disabled, using non-privileged ports")
			}

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			return app.RunServer(ctx)
		},
	}

	rootCmd.Flags().StringVar(&configPath, "config", "", "Path to config.yaml file (optional, searches default locations if not provided)")
	rootCmd.Flags().BoolVarP(&showVersion, "version", "v", false, "Print version and exit")

	if err := rootCmd.Execute(); err != nil {
		app.Logger.Error("Failed to execute command", "error", err)
		os.Exit(1)
	}
}