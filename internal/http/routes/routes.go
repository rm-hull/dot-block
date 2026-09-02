package routes

import (
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rm-hull/dot-block/internal/geoblock"
	"github.com/rm-hull/dot-block/internal/http/handlers"
	"github.com/rm-hull/dot-block/internal/http/middlewares"
	"github.com/rm-hull/dot-block/internal/http/sse"
	"github.com/rm-hull/dot-block/internal/http/web"
	"github.com/rm-hull/dot-block/internal/limiter"
	cachecontrol "go.eigsys.de/gin-cachecontrol/v2"
)

func NewPublicGroup(r *gin.Engine, publicHost string, rateLimiter *limiter.Limiter, mobileConfigHandler gin.HandlerFunc, dohHandler gin.HandlerFunc) *gin.RouterGroup {
	public := r.Group("/")
	public.Use(middlewares.RequireHost(publicHost))
	{
		public.GET("/.mobileconfig", mobileConfigHandler)
		public.GET("/robots.txt", handlers.RobotsTxtHandler)
		doh := public.Group("/dns-query")
		doh.Use(middlewares.RateLimit(rateLimiter))
		doh.Use(cors.New(cors.Config{
			AllowOrigins:  []string{"*"},
			AllowMethods:  []string{http.MethodGet, http.MethodPost, http.MethodOptions},
			AllowHeaders:  []string{"Accept", "Content-Type"},
			ExposeHeaders: []string{"Content-Length"},
			MaxAge:        12 * time.Hour,
		}))
		{
			doh.GET("", dohHandler)
			doh.POST("", dohHandler)
			doh.OPTIONS("", corsPreflightHandler)
		}
	}
	return public
}

func NewAdminGroup(
	r *gin.Engine,
	adminHost string,
	devMode bool,
	apiKeys map[string]string,
	blocklistHandler *handlers.BlocklistHandler,
	broadcaster *sse.Broadcaster,
	geoIp geoblock.GeoIpLookup,
	versionInfoHandler *handlers.VersionInfoHandler,
	rateLimiter *limiter.Limiter,
	dohHandler gin.HandlerFunc,
) *gin.RouterGroup {

	// --- Admin: SPA + API, pinned to the admin host, auth on top ---
	admin := r.Group("/")
	admin.Use(middlewares.RequireHost(adminHost))
	{
		api := admin.Group("/api")
		api.Use(cors.New(cors.Config{
			AllowOrigins:     []string{"*"},
			AllowMethods:     []string{http.MethodGet, http.MethodPost, http.MethodOptions},
			AllowHeaders:     []string{"Authorization", "Content-Type", "X-API-Key"},
			ExposeHeaders:    []string{"Content-Length"},
			AllowCredentials: true,
			MaxAge:           12 * time.Hour,
		}))
		api.Use(middlewares.RequireAnyAuth(middlewares.APIKeyAuth(apiKeys), middlewares.ProxyAuth(devMode)))
		{
			api.OPTIONS("/*path", corsPreflightHandler)
			api.POST("/blocklist/check", blocklistHandler.Check)
			api.POST("/blocklist/reload", blocklistHandler.Reload)
			api.POST("/blocklist/disable", blocklistHandler.Disable)
			api.POST("/blocklist/reenable", blocklistHandler.Reenable)
			api.GET("/blocklist/status", blocklistHandler.Status(""))
			api.GET("/asn/:ip", cachecontrol.NewWithOptions(cachecontrol.WithMaxAge(cachecontrol.Duration(24*time.Hour))), asnLookupHandler(geoIp))
			api.GET("/events", cachecontrol.New(cachecontrol.NoCachePreset), handlers.SSEHandler(broadcaster))
			api.GET("/whoami", whoAmIHandler)
			api.GET("/version-info", versionInfoHandler.Info)
			api.GET("/banned-ips", bannedIPsHandler(rateLimiter))
			api.GET("/metrics", handlers.MetricsJSON(prometheus.DefaultGatherer.(*prometheus.Registry)))
			api.GET("/dns-query", dohHandler)
		}

		distFS := web.DistFS()
		httpFS := http.FS(distFS)
		fileServer := http.FileServer(httpFS)

		r.NoRoute(func(c *gin.Context) {

			host := c.Request.Host
			if i := strings.IndexByte(host, ':'); i != -1 {
				host = host[:i]
			}
			if !strings.EqualFold(host, adminHost) {
				c.AbortWithStatus(http.StatusNotFound)
				return
			}

			path := strings.TrimPrefix(c.Request.URL.Path, "/")
			if path != "" {
				if strings.HasPrefix(path, "api/") {
					c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "API endpoint not found"})
					return
				}
				if _, err := fs.Stat(distFS, path); err == nil {
					fileServer.ServeHTTP(c.Writer, c.Request)
					return
				}
			}

			c.FileFromFS("/", httpFS)
		})
	}

	return admin
}

func corsPreflightHandler(c *gin.Context) {
	c.Status(http.StatusNoContent)
}

func bannedIPsHandler(rateLimiter *limiter.Limiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		banned := rateLimiter.BannedIPs()
		ips := make([]map[string]any, 0, len(banned))
		for ip, until := range banned {
			remaining := time.Until(until)
			secs := int(remaining.Seconds())
			if secs < 0 {
				secs = 0
			}
			ips = append(ips, map[string]any{
				"ip":                ip,
				"banned_until":      until.Format(time.RFC3339),
				"remaining_seconds": secs,
			})
		}
		c.JSON(http.StatusOK, gin.H{"banned_ips": ips})
	}
}

func whoAmIHandler(c *gin.Context) {
	user, _ := c.Get("user")
	email, _ := c.Get("email")
	c.JSON(http.StatusOK, gin.H{
		"user":  user,
		"email": email,
	})
}

func asnLookupHandler(geoIp geoblock.GeoIpLookup) gin.HandlerFunc {
	return func(c *gin.Context) {
		if geoIp == nil {
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "GeoIP lookup service is disabled"})
			return
		}
		ipAddr := c.Param("ip")
		if ipAddr == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "missing IP address"})
			return
		}
		if !geoIp.IsValid(ipAddr) {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid IP address"})
			return
		}

		geoData, err := geoIp.GetAll(ipAddr)
		if err != nil {
			_ = c.Error(err)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		if geoData == nil {
			c.AbortWithStatus(http.StatusNotFound)
			return
		}

		c.JSON(http.StatusOK, geoData)
	}
}
