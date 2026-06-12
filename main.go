package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/rm-hull/dot-block/internal"
	"github.com/rm-hull/dot-block/internal/logging"
	"github.com/spf13/cobra"
)

const DEFAULT_DOWNLOADER_CRON_SCHEDULE = "@every 19h"
const DEFAULT_CACHE_REAPER_CRON_SCHEDULE = "0 3 * * *" // 3:00am every day
const DEFAULT_IP2LOCATION_CRON_SCHEDULE = "5 7 4 * *"  // 7:05am on the 4th of every month

var DEFAULT_NOISE_FILTER_URL = "https://raw.githubusercontent.com/rm-hull/dot-block/refs/heads/main/data/noise-filter.csv"

var DEFAULT_BLOCKLIST_URLS = []string{
	"https://codeberg.org/hagezi/mirror2/raw/branch/main/dns-blocklists/hosts/pro.txt",       // Hagezi Pro blocklist
	"https://raw.githubusercontent.com/rm-hull/dot-block/refs/heads/main/data/blocklist.txt", // dot-block default blocklist
}

var DEFAULT_UPSTREAM_DNS = []string{
	"8.8.8.8", // Google
	"8.8.4.4",
	"1.1.1.1", // Cloudflare
	"1.0.0.1",
}

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
	envDevMode := os.Getenv("DEV_MODE") == "true"

	var dnsPort, dotPort int

	rootCmd := &cobra.Command{
		Use:   "dotserver",
		Short: "DNS-over-TLS server",
		RunE: func(cmd *cobra.Command, args []string) error {
			logLevelVar.Set(parseLogLevel(app.LogLevel))
			app.DnsPort = dnsPort
			app.DotPort = dotPort

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

	rootCmd.Flags().StringVar(&app.LogLevel, "log-level", "INFO", "Log level (DEBUG, INFO, WARN, ERROR)")
	rootCmd.Flags().StringSliceVar(&app.BlockListURLs, "blocklist-url", DEFAULT_BLOCKLIST_URLS, "URL of blocklist, must be wildcard hostname format")
	rootCmd.Flags().StringVar(&app.NoiseFilterURL, "noise-filter-url", DEFAULT_NOISE_FILTER_URL, "URL of noise filter list (CSV format: category,rcode,domain_suffix)")
	rootCmd.Flags().StringVar(&app.DataDir, "data-dir", "./data", "Directory for persisting data (e.g. TLS certificate cache)")
	rootCmd.Flags().BoolVar(&app.DevMode, "dev-mode", envDevMode, "Run server in dev mode (no TLS, plain TCP)")
	rootCmd.Flags().IntVar(&dnsPort, "dns-port", 0, "The port to run regular DNS (UDP/TCP) server on")
	rootCmd.Flags().IntVar(&dotPort, "dot-port", 853, "The port to run DNS-over-TLS server on")
	rootCmd.Flags().StringSliceVar(&app.Upstreams, "upstreams", DEFAULT_UPSTREAM_DNS, "Upstream DNS resolvers to forward queries to")
	rootCmd.Flags().IntVar(&app.HttpPort, "http-port", 80, "The port to run HTTP server on")
	rootCmd.Flags().StringSliceVar(&app.AllowedHosts, "allowed-hosts", nil, "List of domains used for CertManager allow policy")
	rootCmd.Flags().StringVar(&app.MetricsAuth, "metrics-auth", "", "Credentials for basic auth on /metrics (format: `user:pass`)")
	rootCmd.Flags().IntVar(&app.MaxCacheSize, "max-cache-size", 1_000_000, "Maximum number of entries in the DNS cache")
	rootCmd.Flags().StringVar(&app.CronSchedule.Downloader, "cron-schedule:downloader", DEFAULT_DOWNLOADER_CRON_SCHEDULE, "cron spec for reloading blocklist")
	rootCmd.Flags().StringVar(&app.CronSchedule.CacheReaper, "cron-schedule:cache-reaper", DEFAULT_CACHE_REAPER_CRON_SCHEDULE, "cron spec for cache reaper")
	rootCmd.Flags().StringVar(&app.CronSchedule.IP2Location, "cron-schedule:ip2location", DEFAULT_IP2LOCATION_CRON_SCHEDULE, "cron spec for Ip2location downloader")
	rootCmd.Flags().DurationVar(&app.CacheTtlFloor, "cache-ttl-floor", 3600*time.Second, "Minimum TTL for cached entries")
	rootCmd.Flags().DurationVar(&app.Timeouts.Read, "read-timeout", 100*time.Millisecond, "Timeout for reading upstream DNS queries")
	rootCmd.Flags().DurationVar(&app.Timeouts.Write, "write-timeout", 100*time.Millisecond, "Timeout for writing upstream DNS queries")
	rootCmd.Flags().DurationVar(&app.Timeouts.Dial, "dial-timeout", 100*time.Millisecond, "Timeout for establishing connections to upstream servers")
	rootCmd.Flags().BoolVar(&app.RequireProxyProtocol, "require-proxy-protocol", false, "Require PROXY protocol header for DoT connections")
	rootCmd.Flags().StringSliceVar(&app.TrustedProxies, "trusted-proxies", nil, "Comma-separated list of trusted proxy IP addresses or CIDR ranges")
	rootCmd.Flags().BoolVar(&app.EnableECS, "enable-ecs", false, "Enable EDNS0 Client Subnet (ECS) steering")

	if err := rootCmd.Execute(); err != nil {
		app.Logger.Error("Failed to execute command", "error", err)
		os.Exit(1)
	}
}
