package main

import (
	"crypto/tls"
	"dot-block/internal"
	"fmt"
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/miekg/dns"
	"github.com/rm-hull/godx"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/acme/autocert"
)

const host = "dot.destructuring-bind.org"

func main() {
	var (
		upstream string
		cacheDir string
		devMode  bool
	)

	envDevMode := os.Getenv("DEV_MODE") == "true"

	rootCmd := &cobra.Command{
		Use:   "dotserver",
		Short: "DNS-over-TLS server",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServer(host, cacheDir, upstream, devMode)
		},
	}

	rootCmd.Flags().StringVar(&cacheDir, "cache-dir", "./dev/certdata", "Directory for TLS certificate cache")
	rootCmd.Flags().BoolVar(&devMode, "dev-mode", envDevMode, "Run server in dev mode (no TLS, plain TCP)")
	rootCmd.Flags().StringVar(&upstream, "upstream", "1.1.1.1:53", "Upstream DNS resolver to forward queries to")

	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Failed to execute command: %v", err)
	}
}

func runServer(host, cacheDir, upstream string, devMode bool) error {
	godx.GitVersion()
	godx.EnvironmentVars()
	godx.UserInfo()

	dispatcher := internal.NewDNSDispatcher(upstream, 1_000_000)

	manager := &autocert.Manager{
		Cache:      autocert.DirCache(cacheDir),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(host),
	}
	r := gin.Default()
	r.Any("/.well-known/acme-challenge/*path", gin.WrapH(manager.HTTPHandler(nil)))

	go func() {
		port := ":80"
		if devMode {
			port = ":8080"
		}
		log.Printf("Starting HTTP server on port %s for ACME challenge...", port)
		if err := r.Run(port); err != nil {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	if devMode {
		dnsServer := &dns.Server{
			Addr:    ":8053",
			Net:     "tcp",
			Handler: dns.HandlerFunc(dispatcher.HandleDNSRequest),
		}

		log.Println("Starting DNS server in DEV mode on port 8053 (no TLS)...")
		if err := dnsServer.ListenAndServe(); err != nil {
			return fmt.Errorf("failed to start DNS server in dev mode: %w", err)
		}
		return nil
	}

	tlsConfig := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"dot"}, // important for DNS-over-TLS
		GetCertificate: manager.GetCertificate,
	}

	dnsServer := &dns.Server{
		Addr:      ":853",
		Net:       "tcp-tls",
		TLSConfig: tlsConfig,
		Handler:   dns.HandlerFunc(dispatcher.HandleDNSRequest),
	}

	log.Println("Starting DNS-over-TLS server on port 853...")
	if err := dnsServer.ListenAndServe(); err != nil {
		return fmt.Errorf("failed to start DoT server: %v", err)
	}
	return nil
}
