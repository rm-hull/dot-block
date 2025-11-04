package main

import (
	"dot-block/internal"
	"log"
	"os"

	"github.com/spf13/cobra"
)

const HAGEZI_PRO_BLOCKLIST = "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/pro-onlydomains.txt"
const DEFAULT_UPSTREAM_DNS = "1.1.1.1:53"

func main() {
	app := internal.App{}
	envDevMode := os.Getenv("DEV_MODE") == "true"

	rootCmd := &cobra.Command{
		Use:   "dotserver",
		Short: "DNS-over-TLS server",
		RunE: func(cmd *cobra.Command, args []string) error {
			return app.RunServer()
		},
	}

	rootCmd.Flags().StringVar(&app.BlockListUrl, "blocklist-url", HAGEZI_PRO_BLOCKLIST, "URL of blocklist, must be wildcard hostname format")
	rootCmd.Flags().StringVar(&app.CertCacheDir, "cache-dir", "./data/certcache", "Directory for TLS certificate cache")
	rootCmd.Flags().BoolVar(&app.DevMode, "dev-mode", envDevMode, "Run server in dev mode (no TLS, plain TCP)")
	rootCmd.Flags().StringVar(&app.Upstream, "upstream", DEFAULT_UPSTREAM_DNS, "Upstream DNS resolver to forward queries to")
	rootCmd.Flags().IntVar(&app.HttpPort, "http-port", 80, "The port to run HTTP server on")
	rootCmd.Flags().StringArrayVar(&app.AllowedHosts, "allowed-host", nil, "List of domains used for CertManager allow policy")
	rootCmd.Flags().StringVar(&app.MetricsAuth, "metrics-auth", "", "Credentials for basic auth on /metrics (format: `user:pass`)")

	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Failed to execute command: %v", err)
	}
}
