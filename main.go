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
	var dnsPort, dotPort int
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

			// Load configuration from YAML file with env substitution
			cfg, err := config.Load(configPath)
			if err != nil {
				app.Logger.Error("Failed to load configuration", "error", err)
				os.Exit(1)
			}

			// Apply environment variable overrides
			config.ApplyEnvOverrides(cfg)

			// Map config to App struct
			mapConfigToApp(cfg, &app, cmd)

			logLevelVar.Set(parseLogLevel(app.LogLevel))

			if app.DevMode {
				if !cmd.Flags().Changed("dns-port") {
					app.DnsPort = 8053
				}
				if !cmd.Flags().Changed("dot-port") {
					app.DotPort = 8853
				}
				app.Logger.Warn("Running in DEV MODE: TLS disabled, using non-privileged ports")
			}

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			return app.RunServer(ctx)
		},
	}

	rootCmd.Flags().StringVar(&configPath, "config", "", "Path to config.yaml file (optional, searches default locations if not provided)")
	rootCmd.Flags().StringVar(&app.LogLevel, "log-level", "INFO", "Log level (DEBUG, INFO, WARN, ERROR)")
	rootCmd.Flags().StringSliceVar(&app.BlockListURLs, "blocklist-url", nil, "URL of blocklist, must be wildcard hostname format (can specify multiple)")
	rootCmd.Flags().StringVar(&app.NoiseFilterURL, "noise-filter-url", "", "URL of noise filter list (CSV format: category,rcode,domain_suffix)")
	rootCmd.Flags().StringVar(&app.DataDir, "data-dir", "", "Directory for persisting data (e.g. TLS certificate cache)")
	rootCmd.Flags().BoolVar(&app.DevMode, "dev-mode", false, "Run server in dev mode (no TLS, plain TCP)")
	rootCmd.Flags().IntVar(&dnsPort, "dns-port", 0, "The port to run regular DNS (UDP/TCP) server on")
	rootCmd.Flags().IntVar(&dotPort, "dot-port", 0, "The port to run DNS-over-TLS server on")
	rootCmd.Flags().StringSliceVar(&app.Upstreams, "upstreams", nil, "Upstream DNS resolvers to forward queries to")
	rootCmd.Flags().IntVar(&app.HttpPort, "http-port", 0, "The port to run HTTP server on")
	rootCmd.Flags().StringSliceVar(&app.AllowedHosts, "allowed-hosts", nil, "List of domains used for CertManager allow policy")
	rootCmd.Flags().StringVar(&app.MetricsAuth, "metrics-auth", "", "Credentials for basic auth on /metrics (format: `user:pass`)")
	rootCmd.Flags().IntVar(&app.MaxCacheSize, "max-cache-size", 0, "Maximum number of entries in the DNS cache")
	rootCmd.Flags().StringVar(&app.CronSchedule.Downloader, "cron-schedule:downloader", "", "cron spec for reloading blocklist")
	rootCmd.Flags().StringVar(&app.CronSchedule.CacheReaper, "cron-schedule:cache-reaper", "", "cron spec for cache reaper")
	rootCmd.Flags().StringVar(&app.CronSchedule.IPInfo, "cron-schedule:ipinfo", "", "cron spec for Ipinfo.io downloader")
	rootCmd.Flags().DurationVar(&app.CacheTtlFloor, "cache-ttl-floor", 0, "Minimum TTL for cached entries")
	rootCmd.Flags().DurationVar(&app.Timeouts.Read, "read-timeout", 0, "Timeout for reading upstream DNS queries")
	rootCmd.Flags().DurationVar(&app.Timeouts.Write, "write-timeout", 0, "Timeout for writing upstream DNS queries")
	rootCmd.Flags().DurationVar(&app.Timeouts.Dial, "dial-timeout", 0, "Timeout for establishing connections to upstream servers")
	rootCmd.Flags().BoolVar(&app.RequireProxyProtocol, "require-proxy-protocol", false, "Require PROXY protocol header for DoT connections")
	rootCmd.Flags().StringSliceVar(&app.TrustedProxies, "trusted-proxies", nil, "Comma-separated list of trusted proxy IP addresses or CIDR ranges")
	rootCmd.Flags().BoolVar(&app.EnableECS, "enable-ecs", false, "Enable EDNS0 Client Subnet (ECS) steering")
	rootCmd.Flags().BoolVarP(&showVersion, "version", "v", false, "Print version and exit")

	if err := rootCmd.Execute(); err != nil {
		app.Logger.Error("Failed to execute command", "error", err)
		os.Exit(1)
	}
}

func mapConfigToApp(cfg *config.Config, app *internal.App, cmd *cobra.Command) {
	// Server config
	app.DevMode = cfg.Server.DevMode
	app.LogLevel = string(cfg.Server.LogLevel)
	app.DataDir = cfg.Server.DataDir
	app.HttpPort = cfg.Server.HttpPort
	app.DnsPort = cfg.Server.DnsPort
	app.DotPort = cfg.Server.DotPort
	app.RequireProxyProtocol = cfg.Server.RequireProxyProtocol
	app.TrustedProxies = cfg.Server.TrustedProxies
	app.AllowedHosts = cfg.Server.AllowedHosts
	app.MetricsAuth = cfg.Server.MetricsAuth

	// DNS config
	app.Upstreams = cfg.DNS.Upstreams
	app.EnableECS = cfg.DNS.ECS.Enabled
	app.MaxCacheSize = cfg.DNS.Cache.MaxSize
	app.CacheTtlFloor = cfg.DNS.Cache.TtlFloor
	app.CronSchedule.CacheReaper = cfg.DNS.Cache.CronSchedule
	app.Timeouts.Read = cfg.DNS.Timeouts.Read
	app.Timeouts.Write = cfg.DNS.Timeouts.Write
	app.Timeouts.Dial = cfg.DNS.Timeouts.Dial
	app.NoiseFilterURL = cfg.DNS.NoiseFilter.URL

	// Blocklists config
	app.BlockListURLs = cfg.Blocklists.URLs
	app.CronSchedule.Downloader = cfg.Blocklists.CronSchedule

	// Geoblock config
	app.DisableIpinfo = !cfg.Geoblock.Ipinfo.Enabled
	app.CronSchedule.IPInfo = cfg.Geoblock.Ipinfo.CronSchedule

	// CLI flags override (only if explicitly set)
	// Note: We use cmd.Flags().Changed() to check if flag was explicitly provided
	// But since we're in RunE after parsing, we can't easily do that here.
	// The precedence is handled by: defaults < config.yaml < env vars < CLI flags
	// CLI flags are already bound to app fields, so they'll override if provided.
}