package main

import (
	"log"
	"os"

	"github.com/rm-hull/dot-block/internal"

	"github.com/spf13/cobra"
)

const HAGEZI_PRO_BLOCKLIST = "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/pro-onlydomains.txt"

var DEFAULT_UPSTREAM_DNS = []string{
	"8.8.8.8:53", // Google
	"8.8.4.4:53",
	"1.1.1.1:53", // Cloudflare
	"1.0.0.1:53",
}

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
	rootCmd.Flags().StringArrayVar(&app.Upstreams, "upstream", DEFAULT_UPSTREAM_DNS, "Upstream DNS resolvers to forward queries to")
	rootCmd.Flags().IntVar(&app.HttpPort, "http-port", 80, "The port to run HTTP server on")
	rootCmd.Flags().StringArrayVar(&app.AllowedHosts, "allowed-host", nil, "List of domains used for CertManager allow policy")
	rootCmd.Flags().StringVar(&app.MetricsAuth, "metrics-auth", "", "Credentials for basic auth on /metrics (format: `user:pass`)")

	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Failed to execute command: %v", err)
	}
}
