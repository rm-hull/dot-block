package internal

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/Depado/ginprom"
	"github.com/caddyserver/certmagic"
	"github.com/cockroachdb/errors"
	"github.com/earthboundkid/versioninfo/v2"
	"github.com/getsentry/sentry-go"
	sentrygin "github.com/getsentry/sentry-go/gin"
	"github.com/gin-contrib/pprof"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/libdns/cloudflare"
	"github.com/miekg/dns"
	"github.com/pires/go-proxyproto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rm-hull/dot-block/internal/blocklist"
	"github.com/rm-hull/dot-block/internal/config"
	"github.com/rm-hull/dot-block/internal/forwarder"
	"github.com/rm-hull/dot-block/internal/geoblock"
	"github.com/rm-hull/dot-block/internal/http/handlers"
	"github.com/rm-hull/dot-block/internal/http/middlewares"
	"github.com/rm-hull/dot-block/internal/http/routes"
	"github.com/rm-hull/dot-block/internal/http/sse"
	"github.com/rm-hull/dot-block/internal/logging"
	"github.com/rm-hull/dot-block/internal/metrics"
	"github.com/rm-hull/dot-block/internal/noisefilter"
	"github.com/rm-hull/dot-block/internal/telemetry"
	"github.com/rm-hull/godx"
	"github.com/robfig/cron/v3"
	sloggin "github.com/samber/slog-gin"
	healthcheck "github.com/tavsec/gin-healthcheck"
	hc_config "github.com/tavsec/gin-healthcheck/config"
	"golang.org/x/sync/errgroup"
)

type App struct {
	Logger    *slog.Logger
	Config    *config.Config
	StartTime time.Time
}

func (app *App) monitorShutdown(ctx context.Context, name string, shutdownFn func() error) {
	go func() {
		<-ctx.Done()
		if err := shutdownFn(); err != nil {
			app.Logger.Error(name+" failed to shut down", "error", err)
		} else {
			app.Logger.Info(name + " shut down successfully")
		}
	}()
}

func (app *App) RunServer(ctx context.Context) error {
	app.StartTime = time.Now()
	if err := godotenv.Load(); err != nil {
		app.Logger.Warn("No .env file found")
	}
	godx.Diagnostics(app.Logger)
	app.Logger.Info("Configuration on startup", "config", app.Config)
	shutdownTracer, err := telemetry.InitTracer(app.Logger, "dot-block", app.Config.Telemetry.OtelEndpoint, app.Config.Telemetry.OtelSamplingRatio)
	if err != nil {
		app.Logger.Error("failed to initialize tracing", "error", err)
	} else {
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := shutdownTracer(ctx); err != nil {
				app.Logger.Error("failed to shutdown tracer", "error", err)
			}
		}()
	}
	err = sentry.Init(sentry.ClientOptions{
		Dsn:         app.Config.Telemetry.SentryDsn,
		Debug:       app.Config.Server.DevMode,
		Release:     versioninfo.Revision[:7],
		Environment: app.environment(),
	})
	if err != nil {
		app.Logger.Error("sentry.Init failed", "error", err)
	}
	defer sentry.Flush(2 * time.Second)
	adapter := logging.NewCronLoggerAdapter(app.Logger, "cron")
	crontab := cron.New(cron.WithChain(cron.Recover(adapter)), cron.WithLogger(adapter))
	crontab.Start()
	defer crontab.Stop()
	var geoIpLookup geoblock.GeoIpLookup
	if !app.Config.Geoblock.Ipinfo.Enabled {
		app.Logger.Warn("GeoData lookups via ipinfo.io are disabled")
	} else {
		geoIpLookup, err = app.initMaxmind(crontab)
		if err != nil {
			return errors.Wrap(err, "failed to initialize GeoData database")
		}
	}
	blockLists, err := app.NewBlockLists(crontab)
	if err != nil {
		return errors.Wrap(err, "failed to create blocklist(s)")
	}

	noiseFilter := noisefilter.NewNoiseFilter()
	if err := noisefilter.Fetch(app.Config.DNS.NoiseFilter.URL, noiseFilter, app.Logger); err != nil {
		app.Logger.Error("failed to download noise filter", "url", app.Config.DNS.NoiseFilter.URL, "error", err)
	}

	app.Logger.Info("Creating noise filter downloader cron job", "schedule", app.Config.DNS.NoiseFilter.CronSchedule)
	noiseFilterUpdater := noisefilter.NewNoiseFilterUpdater(noiseFilter, app.Config.DNS.NoiseFilter.URL, app.Logger)
	if _, err = crontab.AddJob(app.Config.DNS.NoiseFilter.CronSchedule, noiseFilterUpdater); err != nil {
		return errors.Wrap(err, "failed to create noise filter downloader cron job")
	}
	certCacheDir := fmt.Sprintf("%s/certcache", app.Config.Server.DataDir)
	if err := os.MkdirAll(certCacheDir, 0700); err != nil {
		return errors.Wrap(err, "failed to create certcache directory")
	}
	// certmagic setup
	zapLogger := logging.NewZapLoggerAdapter(app.Logger, "certmagic")
	certmagic.Default.Logger = zapLogger
	certmagic.DefaultACME.Logger = zapLogger
	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.Email = app.Config.Server.LetsEncrypt.Email
	certmagic.Default.Storage = &certmagic.FileStorage{Path: certCacheDir}
	var magic *certmagic.Config
	if app.Config.Server.LetsEncrypt.Enabled {
		token := app.Config.Server.LetsEncrypt.CloudflareApiToken
		if token == "" {
			return errors.New("cloudflare_api_token is required for DNS-01 challenge (configure under server.lets_encrypt)")
		}
		certmagic.DefaultACME.DNS01Solver = &certmagic.DNS01Solver{
			DNSManager: certmagic.DNSManager{
				DNSProvider: &cloudflare.Provider{
					APIToken: token,
				},
			},
		}
		magic = certmagic.NewDefault()
		if err := magic.ManageSync(context.Background(), app.Config.Server.LetsEncrypt.AllowedHosts); err != nil {
			return errors.Wrap(err, "failed to manage certificates")
		}
	}
	cache := forwarder.NewDNSCache(app.Config.DNS.Cache.MaxSize, app.Logger)
	metrics, err := metrics.NewDNSMetrics(cache, geoIpLookup, metrics.TopKConfig{
		NumDomains: app.Config.Telemetry.TopK.NumDomains,
		NumBlocked: app.Config.Telemetry.TopK.NumBlocked,
		NumClients: app.Config.Telemetry.TopK.NumClients,
	})
	if err != nil {
		return errors.Wrap(err, "failed to initialize metrics")
	}
	dnsClient, err := forwarder.NewRoundRobinClient(metrics, app.Config.DNS.Timeouts.Read, app.Config.DNS.Timeouts.Write, app.Config.DNS.Timeouts.Dial, app.Logger, app.Config.DNS.Upstreams...)
	if err != nil {
		return errors.Wrap(err, "failed to initialize upstream DNS client")
	}

	broadcaster := sse.NewBroadcaster(app.Logger, metrics.DroppedSSEEvents)
	dispatcher, err := forwarder.NewDNSDispatcher(cache, metrics, dnsClient, blockLists, noiseFilter, broadcaster, app.Config.DNS.Cache.TtlFloor, app.Logger, app.Config.DNS.ECS.Enabled)
	if err != nil {
		return errors.Wrap(err, "failed to create dispatcher")
	}
	defer dispatcher.Close()

	r, err := app.startHttpServer(dnsClient, blockLists, dispatcher, geoIpLookup, handlers.NewVersionInfoHandler(app.StartTime))
	if err != nil {
		return errors.Wrap(err, "failed to initialize HTTP server")
	}

	app.Logger.Info("Creating cache reaper cron job", "schedule", app.Config.DNS.Cache.CronSchedule)
	if _, err = crontab.AddJob(app.Config.DNS.Cache.CronSchedule, forwarder.NewCacheReaperCronJob(dispatcher)); err != nil {
		return errors.Wrap(err, "failed to create cache reaper cron job")
	}
	group, groupCtx := errgroup.WithContext(ctx)
	group.Go(func() error {
		app.Logger.Info("Starting HTTP server for mobileconfig, metrics & healthcheck", "port", app.Config.Server.HttpPort)
		srv := &http.Server{
			Addr:    fmt.Sprintf(":%d", app.Config.Server.HttpPort),
			Handler: r,
		}
		app.monitorShutdown(groupCtx, "HTTP server", func() error {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return srv.Shutdown(shutdownCtx)
		})
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			return errors.Wrap(err, "HTTP server failed")
		}
		return nil
	})
	group.Go(func() error {
		if app.Config.Server.DnsPort == 0 {
			app.Logger.Warn("Skipping UDP DNS server: dns-port not specified")
			return nil
		}
		app.Logger.Info("Starting UDP DNS server", "port", app.Config.Server.DnsPort)
		srv := &dns.Server{
			Addr:    fmt.Sprintf(":%d", app.Config.Server.DnsPort),
			Net:     "udp",
			Handler: dns.HandlerFunc(dispatcher.HandleDNSRequest(forwarder.SourceUDP)),
		}
		app.monitorShutdown(groupCtx, "UDP DNS server", srv.Shutdown)
		return srv.ListenAndServe()
	})
	group.Go(func() error {
		if app.Config.Server.DnsPort == 0 {
			app.Logger.Warn("Skipping TCP DNS server: dns-port not specified")
			return nil
		}
		app.Logger.Info("Starting TCP DNS server", "port", app.Config.Server.DnsPort)
		srv := &dns.Server{
			Addr:    fmt.Sprintf(":%d", app.Config.Server.DnsPort),
			Net:     "tcp",
			Handler: dns.HandlerFunc(dispatcher.HandleDNSRequest(forwarder.SourceTCP)),
		}
		app.monitorShutdown(groupCtx, "TCP DNS server", srv.Shutdown)
		return srv.ListenAndServe()
	})
	group.Go(func() error {
		dotPort := fmt.Sprintf(":%d", app.Config.Server.DotPort)
		listener, err := net.Listen("tcp", dotPort)
		if err != nil {
			return errors.Wrap(err, "failed to create DoT listener")
		}
		defer func() {
			err := listener.Close()
			if err != nil {
				app.Logger.Warn("error closing DoT listener", "error", err)
			}
		}()
		if app.Config.Server.DevMode {
			app.Logger.Info("Starting DoT server (plain TCP) in DEV mode", "port", app.Config.Server.DotPort)
		} else {
			app.Logger.Info("Starting DNS-over-TLS server", "port", app.Config.Server.DotPort)
			proxyListener, err := app.newProxyListener(listener)
			if err != nil {
				return err
			}
			listener = tls.NewListener(proxyListener, &tls.Config{
				MinVersion: tls.VersionTLS12,
				MaxVersion: tls.VersionTLS13,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				},
				NextProtos:     []string{"dot"},
				GetCertificate: magic.GetCertificate,
			})
		}
		srv := &dns.Server{
			Addr:     dotPort,
			Net:      "tcp",
			Listener: listener,
			Handler:  dns.HandlerFunc(dispatcher.HandleDNSRequest(forwarder.SourceDoT)),
		}
		app.monitorShutdown(groupCtx, "DoT server", srv.Shutdown)
		return srv.ActivateAndServe()
	})
	return group.Wait()
}

func (app *App) newProxyListener(base net.Listener) (*proxyproto.Listener, error) {
	var proxyListener *proxyproto.Listener
	pp := app.Config.Server.ProxyProtocol
	if pp != nil && len(pp.TrustedProxies) > 0 {
		// If trusted proxies are specified, use a whitelist policy
		app.Logger.Info("Using PROXY protocol with trusted proxy whitelist", "trusted_proxies", pp.TrustedProxies)
		policy, err := proxyproto.PolicyFromRanges(pp.TrustedProxies, proxyproto.USE, proxyproto.REJECT)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create trusted proxy whitelist policy")
		}
		proxyListener = &proxyproto.Listener{
			Listener:   base,
			ConnPolicy: policy,
		}
	} else if pp != nil && pp.Enabled {
		// If no trusted proxies specified but requirement is on, use REQUIRE policy
		proxyListener = &proxyproto.Listener{
			Listener: base,
			Policy: func(upstream net.Addr) (proxyproto.Policy, error) {
				return proxyproto.REQUIRE, nil
			},
		}
	} else {
		// If requirement is off, use USE policy (optional)
		app.Logger.Warn("Running with PROXY protocol optional; client IPs may be spoofed if not behind a trusted proxy")
		proxyListener = &proxyproto.Listener{
			Listener: base,
			Policy: func(upstream net.Addr) (proxyproto.Policy, error) {
				return proxyproto.USE, nil
			},
		}
	}
	return proxyListener, nil
}

func (app *App) startHttpServer(
	dnsClient *forwarder.RoundRobinClient,
	blocklists []*blocklist.BlockList,
	dispatcher *forwarder.DNSDispatcher,
	geoIpLookup geoblock.GeoIpLookup,
	versionInfoHandler *handlers.VersionInfoHandler,
) (*gin.Engine, error) {

	if !app.Config.Server.DevMode {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.New()
	if app.Config.Server.DevMode {
		app.Logger.Warn("pprof endpoints are enabled and exposed. Do not run with this flag in production.")
		pprof.Register(r)
	}
	prometheus := ginprom.New(
		ginprom.Path("/metrics"),
		ginprom.Ignore("/healthz", "/metrics"),
	)
	r.Use(
		sentrygin.New(sentrygin.Options{
			Repanic:         true,
			WaitForDelivery: false,
			Timeout:         5 * time.Second,
		}),
		gin.Recovery(),
		sloggin.NewWithConfig(app.Logger, *newStructuredLoggingConfig()),
		prometheus.Instrument(),
		middlewares.SentryErrorHandler(app.Logger),
	)
	if err := healthcheck.New(r, hc_config.DefaultConfig(), dnsClient.Healthchecks()); err != nil {
		return nil, errors.Wrap(err, "failed to initialize healthcheck")
	}

	basicAuthMiddleware, err := middlewares.RequireBasicAuth(app.Config.Telemetry.MetricsAuth, app.Logger)
	if err != nil {
		return nil, errors.Wrap(err, "basic auth middleware failure")
	}
	r.GET("/metrics", basicAuthMiddleware, gin.WrapH(promhttp.Handler()))

	if len(app.Config.Server.LetsEncrypt.AllowedHosts) == 0 {
		return nil, errors.New("cannot create mobileconfig handler: at least one hostname must be configured via server.lets_encrypt.allowed_hosts")
	}
	serverName := app.Config.Server.LetsEncrypt.AllowedHosts[0]

	requestHandler := dns.HandlerFunc(dispatcher.HandleDNSRequest(forwarder.SourceDoH))

	routes.NewPublicGroup(r, serverName,
		handlers.NewMobileconfigHandler(serverName),
		handlers.NewDoHHandler(requestHandler))

	routes.NewAdminGroup(r, "admin."+serverName, app.Config.Server.DevMode,
		handlers.NewBlocklistHandler(blocklists, app.Logger),
		dispatcher.GetBroadcaster(),
		geoIpLookup,
		versionInfoHandler,
	)

	return r, nil
}

func (app *App) environment() string {
	if app.Config.Server.DevMode {
		return "DEVELOPMENT"
	}
	return "PRODUCTION"
}

func newStructuredLoggingConfig() *sloggin.Config {
	config := sloggin.DefaultConfig()
	config.WithUserAgent = true
	config.WithClientIP = true
	config.Filters = append(config.Filters, sloggin.IgnorePath("/healthz", "/metrics", "/dns-query"))
	return &config
}

func (app *App) initMaxmind(crontab *cron.Cron) (geoblock.GeoIpLookup, error) {
	geolocationDb := fmt.Sprintf("%s/maxmind/ipinfo_lite.mmdb", app.Config.Server.DataDir)
	if _, err := os.Stat(geolocationDb); os.IsNotExist(err) {
		app.Logger.Info("ipinfo.io database not found, downloading...")
		_, err = geoblock.Fetch(geolocationDb, app.Config.Geoblock.Ipinfo.Token, app.Logger)
		if err != nil {
			return nil, errors.Wrap(err, "failed to download ipinfo.io database")
		}
	}
	app.Logger.Info("Loading maxmind database", "file", geolocationDb)
	geoIpLookup, err := geoblock.NewGeoIpLookup(geolocationDb, app.Logger)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open ipinfo.io database")
	}
	app.Logger.Info("Creating ipinfo.io updater cron job", "schedule", app.Config.Geoblock.Ipinfo.CronSchedule)
	if _, err = crontab.AddJob(app.Config.Geoblock.Ipinfo.CronSchedule, geoblock.NewIpinfoUpdaterCronJob(app.Logger, geolocationDb, app.Config.Geoblock.Ipinfo.Token, geoIpLookup)); err != nil {
		return nil, errors.Wrap(err, "failed to create ipinfo.io updater cron job")
	}
	return geoIpLookup, nil
}

func (app *App) NewBlockLists(crontab *cron.Cron) ([]*blocklist.BlockList, error) {
	blockLists := make([]*blocklist.BlockList, 0, len(app.Config.Blocklist.Sources))
	for idx, source := range app.Config.Blocklist.Sources {
		blockList := blocklist.NewBlockList(source.Name, source.CronSchedule, source.URL, 0.0001, app.Logger)
		blockLists = append(blockLists, blockList)

		if source.CronSchedule == "" {
			continue
		}
		app.Logger.Info("Creating blocklist downloader cron job", "name", source.Name, "schedule", source.CronSchedule)
		// Create a per-source updater that only updates this one blocklist
		singleUpdater := blocklist.NewUpdater(blockLists[idx], 1*time.Minute)
		if _, err := crontab.AddJob(source.CronSchedule, singleUpdater); err != nil {
			return nil, errors.Wrapf(err, "failed to create blocklist downloader cron job for %s", source.Name)
		}

		go singleUpdater.Run()
	}

	return blockLists, nil
}
