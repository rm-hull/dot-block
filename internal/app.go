package internal

import (
	"crypto/tls"
	"fmt"
	"log"
	"strings"

	"github.com/Depado/ginprom"
	"github.com/gin-contrib/pprof"
	"github.com/gin-gonic/gin"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rm-hull/godx"
	healthcheck "github.com/tavsec/gin-healthcheck"
	"github.com/tavsec/gin-healthcheck/checks"
	hc_config "github.com/tavsec/gin-healthcheck/config"
	"golang.org/x/crypto/acme/autocert"
)

const CACHE_SIZE = 1_000_000

type App struct {
	Upstream     string
	CertCacheDir string
	BlockListUrl string
	DevMode      bool
	HttpPort     int
	AllowedHosts []string
	MetricsAuth  string
}

func (app *App) RunServer() error {
	godx.GitVersion()
	godx.EnvironmentVars()
	godx.UserInfo()

	hosts, err := DownloadBlocklist(app.BlockListUrl)
	if err != nil {
		return fmt.Errorf("failed to download blocklist: %w", err)
	}

	blockList := NewBlockList(hosts, 0.0001)

	manager := &autocert.Manager{
		Cache:      autocert.DirCache(app.CertCacheDir),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(app.AllowedHosts...),
	}

	if _, err := app.startHttpServer(manager); err != nil {
		return fmt.Errorf("failed to start HTTP server: %w", err)
	}

	dispatcher, err := NewDNSDispatcher(app.Upstream, blockList, CACHE_SIZE)
	if err != nil {
		return fmt.Errorf("failed to create dispatcher: %w", err)
	}

	if app.DevMode {
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

func (app *App) startHttpServer(manager *autocert.Manager) (*gin.Engine, error) {
	if !app.DevMode {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()

	if app.DevMode {
		log.Println("WARNING: pprof endpoints are enabled and exposed. Do not run with this flag in production.")
		pprof.Register(r)
	}

	prometheus := ginprom.New(
		ginprom.Path("/metrics"),
		ginprom.Ignore("/healthz", "/metrics"),
	)

	r.Use(
		gin.Recovery(),
		gin.LoggerWithWriter(gin.DefaultWriter, "/healthz", "/metrics"),
		prometheus.Instrument(),
	)

	if err := healthcheck.New(r, hc_config.DefaultConfig(), []checks.Check{}); err != nil {
		return nil, fmt.Errorf("failed to initialize healthcheck: %w", err)
	}

	if app.MetricsAuth == "" {
		log.Println("WARNING: metrics endpoint is not protected by basic auth")
		r.GET("/metrics", gin.WrapH(promhttp.Handler()))

	} else {
		parts := strings.SplitN(app.MetricsAuth, ":", 2)
		if len(parts) == 2 {
			log.Println("Protecting /metrics endpoint with basic auth")
			user := parts[0]
			pass := parts[1]
			authorized := r.Group("/", gin.BasicAuth(gin.Accounts{
				user: pass,
			}))
			authorized.GET("/metrics", gin.WrapH(promhttp.Handler()))

		} else {
			return nil, fmt.Errorf("invalid metrics-auth value: %s", app.MetricsAuth)
		}
	}

	r.Any("/.well-known/acme-challenge/*path", gin.WrapH(manager.HTTPHandler(nil)))

	go func() {
		port := fmt.Sprintf(":%d", app.HttpPort)
		log.Printf("Starting HTTP server on port %s for ACME challenge, metrics & healthcheck...", port)
		if err := r.Run(port); err != nil {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	return r, nil
}
