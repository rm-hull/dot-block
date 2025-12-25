package main

import (
	"log/slog"
	"os"

	"github.com/rm-hull/dot-block/internal"
	"github.com/spf13/cobra"
)

const DEFAULT_DOWNLOADER_CRON_SCHEDULE = "@every 19h"
const DEFAULT_CACHE_REAPER_CRON_SCHEDULE = "@every 10m"
const HAGEZI_PRO_BLOCKLIST = "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/pro-onlydomains.txt"

var DEFAULT_UPSTREAM_DNS = []string{
	"8.8.8.8:53", // Google
	"8.8.4.4:53",
	"1.1.1.1:53", // Cloudflare
	"1.0.0.1:53",
	"9.9.9.9:53", // Quad9
	"149.112.112.112:53",
}

func main() {
	app := internal.App{
		Logger: slog.New(slog.NewTextHandler(os.Stderr, nil)),
	}
	envDevMode := os.Getenv("DEV_MODE") == "true"

	var dnsPort, dotPort int

	rootCmd := &cobra.Command{
		Use:   "dotserver",
		Short: "DNS-over-TLS server",
		RunE: func(cmd *cobra.Command, args []string) error {
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

			return app.RunServer()
		},
	}

	rootCmd.Flags().StringVar(&app.BlockListUrl, "blocklist-url", HAGEZI_PRO_BLOCKLIST, "URL of blocklist, must be wildcard hostname format")
	rootCmd.Flags().StringVar(&app.DataDir, "data-dir", "./data", "Directory for persisting data (e.g. TLS certificate cache)")
	rootCmd.Flags().BoolVar(&app.DevMode, "dev-mode", envDevMode, "Run server in dev mode (no TLS, plain TCP)")
	rootCmd.Flags().IntVar(&dnsPort, "dns-port", 53, "The port to run regular DNS (UDP/TCP) server on")
	rootCmd.Flags().IntVar(&dotPort, "dot-port", 853, "The port to run DNS-over-TLS server on")
	rootCmd.Flags().StringArrayVar(&app.Upstreams, "upstream", DEFAULT_UPSTREAM_DNS, "Upstream DNS resolvers to forward queries to")
	rootCmd.Flags().IntVar(&app.HttpPort, "http-port", 80, "The port to run HTTP server on")
	rootCmd.Flags().StringArrayVar(&app.AllowedHosts, "allowed-host", nil, "List of domains used for CertManager allow policy")
	rootCmd.Flags().StringVar(&app.MetricsAuth, "metrics-auth", "", "Credentials for basic auth on /metrics (format: `user:pass`)")
	rootCmd.Flags().StringVar(&app.CronSchedule.Downloader, "cron-schedule:downloader", DEFAULT_DOWNLOADER_CRON_SCHEDULE, "cron spec for reloading blocklist")
	rootCmd.Flags().StringVar(&app.CronSchedule.CacheReaper, "cron-schedule:cache-reaper", DEFAULT_CACHE_REAPER_CRON_SCHEDULE, "cron spec for cache reaper")

	if err := rootCmd.Execute(); err != nil {
		app.Logger.Error("Failed to execute command", "error", err)
		os.Exit(1)
	}
}
