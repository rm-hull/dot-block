package routes

import (
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/rm-hull/dot-block/internal/geoblock"
	"github.com/rm-hull/dot-block/internal/http/handlers"
	"github.com/rm-hull/dot-block/internal/http/middlewares"
	"github.com/rm-hull/dot-block/internal/http/sse"
	"github.com/rm-hull/dot-block/internal/http/web"
	cachecontrol "go.eigsys.de/gin-cachecontrol/v2"
)

func NewPublicGroup(r *gin.Engine, publicHost string, mobileConfigHandler gin.HandlerFunc, dohHandler gin.HandlerFunc) *gin.RouterGroup {
	public := r.Group("/")
	public.Use(middlewares.RequireHost(publicHost))
	{
		public.GET("/.mobileconfig", mobileConfigHandler)
		public.GET("/robots.txt", handlers.RobotsTxtHandler)
		public.GET("/dns-query", dohHandler)
		public.POST("/dns-query", dohHandler)
	}
	return public
}

func NewAdminGroup(
	r *gin.Engine,
	adminHost string,
	devMode bool,
	blocklistCheckHandler gin.HandlerFunc,
	blocklistReloadHandler gin.HandlerFunc,
	broadcaster *sse.Broadcaster,
	geoIp geoblock.GeoIpLookup,
) *gin.RouterGroup {

	// --- Admin: SPA + API, pinned to the admin host, auth on top ---
	admin := r.Group("/")
	admin.Use(middlewares.RequireHost(adminHost))
	{
		api := admin.Group("/api")
		api.Use(cors.New(cors.Config{
			AllowOrigins:     []string{"*"},
			AllowMethods:     []string{http.MethodGet, http.MethodPost, http.MethodOptions},
			AllowHeaders:     []string{"Authorization", "Content-Type"},
			ExposeHeaders:    []string{"Content-Length"},
			AllowCredentials: true,
			MaxAge:           12 * time.Hour,
		}))
		api.Use(middlewares.RequireProxyAuth(devMode))
		{
			api.OPTIONS("/*path", corsPreflightHandler)
			api.POST("/blocklist/check", blocklistCheckHandler)
			api.POST("/blocklist/reload", blocklistReloadHandler)
			api.GET("/asn/:ip", cachecontrol.NewWithOptions(cachecontrol.WithMaxAge(cachecontrol.Duration(24*time.Hour))), asnLookupHandler(geoIp))
			api.GET("/events", cachecontrol.New(cachecontrol.NoCachePreset), sseHandler(broadcaster))
			api.GET("/whoami", whoAmIHandler)
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

func sseHandler(broadcaster *sse.Broadcaster) gin.HandlerFunc {
	return func(c *gin.Context) {
		if broadcaster == nil {
			c.AbortWithStatus(http.StatusServiceUnavailable)
			return
		}
		subscriber := broadcaster.Subscribe()
		defer broadcaster.Unsubscribe(subscriber)

		c.Header("Content-Type", "text/event-stream")
		c.Header("Connection", "keep-alive")

		for {
			select {
			case event, ok := <-subscriber:
				if !ok {
					return
				}
				c.SSEvent("message", event)
				c.Writer.Flush()
			case <-c.Request.Context().Done():
				return
			}
		}
	}
}

func corsPreflightHandler(c *gin.Context) {
	c.Status(http.StatusNoContent)
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
