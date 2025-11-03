package main

import (
	"crypto/tls"
	"dot-block/internal"
	"fmt"
	"log"
	"os"

	"github.com/Depado/ginprom"
	"github.com/gin-gonic/gin"
	"github.com/miekg/dns"
	"github.com/rm-hull/godx"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/acme/autocert"
)

const HAGEZI_PRO_BLOCKLIST = "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/pro-onlydomains.txt"
const DEFAULT_UPSTREAM_DNS = "1.1.1.1:53"
const CACHE_SIZE = 1_000_000

func main() {
	var (
		upstream     string
		cacheDir     string
		blockListUrl string
		devMode      bool
		httpPort     int
		allowedHosts []string
	)

	envDevMode := os.Getenv("DEV_MODE") == "true"

	rootCmd := &cobra.Command{
		Use:   "dotserver",
		Short: "DNS-over-TLS server",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServer(allowedHosts, cacheDir, upstream, blockListUrl, devMode, httpPort)
		},
	}

	rootCmd.Flags().StringVar(&blockListUrl, "blocklist-url", HAGEZI_PRO_BLOCKLIST, "URL of blocklist, must be wildcard hostname format")
	rootCmd.Flags().StringVar(&cacheDir, "cache-dir", "./data/certcache", "Directory for TLS certificate cache")
	rootCmd.Flags().BoolVar(&devMode, "dev-mode", envDevMode, "Run server in dev mode (no TLS, plain TCP)")
	rootCmd.Flags().StringVar(&upstream, "upstream", DEFAULT_UPSTREAM_DNS, "Upstream DNS resolver to forward queries to")
	rootCmd.Flags().IntVar(&httpPort, "http-port", 80, "The port to run HTTP server on")
	rootCmd.Flags().StringArrayVar(&allowedHosts, "allowed-host", nil, "List of domains used for CertManager allow policy")

	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Failed to execute command: %v", err)
	}
}

func runServer(allowedHosts []string, cacheDir, upstream, blockListUrl string, devMode bool, httpPort int) error {
	godx.GitVersion()
	godx.EnvironmentVars()
	godx.UserInfo()

	hosts, err := internal.DownloadBlocklist(blockListUrl)
	if err != nil {
		return fmt.Errorf("failed to download blocklist: %w", err)
	}

	blockList := internal.NewBlockList(hosts, 0.0001)

	manager := &autocert.Manager{
		Cache:      autocert.DirCache(cacheDir),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(allowedHosts...),
	}

	startHttpServer(devMode, httpPort, manager)

	dispatcher := internal.NewDNSDispatcher(upstream, blockList, CACHE_SIZE)

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

func startHttpServer(devMode bool, httpPort int, manager *autocert.Manager) *gin.Engine {

	if !devMode {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()
	prometheus := ginprom.New(
		ginprom.Engine(r),
		ginprom.Path("/metrics"),
		ginprom.Ignore("/healthz"),
	)

	r.Use(
		gin.Recovery(),
		gin.LoggerWithWriter(gin.DefaultWriter, "/metrics"),
		prometheus.Instrument(),
	)

	r.Any("/.well-known/acme-challenge/*path", gin.WrapH(manager.HTTPHandler(nil)))

	go func() {
		port := fmt.Sprintf(":%d", httpPort)
		log.Printf("Starting HTTP server on port %s for ACME challenge & metrics...", port)
		if err := r.Run(port); err != nil {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	return r
}
