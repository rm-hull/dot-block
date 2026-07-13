package routes

import (
	"io/fs"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/rm-hull/dot-block/internal/http/handlers"
	"github.com/rm-hull/dot-block/internal/http/middlewares"
	"github.com/rm-hull/dot-block/internal/http/sse"
	"github.com/rm-hull/dot-block/internal/http/web"
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

func NewAdminGroup(r *gin.Engine, adminHost string, devMode bool, blocklistCheckHandler gin.HandlerFunc, blocklistReloadHandler gin.HandlerFunc, broadcaster *sse.Broadcaster) *gin.RouterGroup {

	// --- Admin: SPA + API, pinned to the admin host, auth on top ---
	admin := r.Group("/")
	admin.Use(middlewares.RequireHost(adminHost))
	{
		api := admin.Group("/api")
		api.Use(middlewares.RequireProxyAuth(devMode))
		{
			api.POST("/check", blocklistCheckHandler)
			api.POST("/reload", blocklistReloadHandler)
			api.GET("/events", func(c *gin.Context) {
				if broadcaster == nil {
					c.AbortWithStatus(http.StatusServiceUnavailable)
					return
				}
				subscriber := broadcaster.Subscribe()
				defer broadcaster.Unsubscribe(subscriber)

				c.Header("Content-Type", "text/event-stream")
				c.Header("Cache-Control", "no-cache")
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
			})
			api.GET("/whoami", func(c *gin.Context) {
				user, _ := c.Get("user")
				email, _ := c.Get("email")
				c.JSON(http.StatusOK, gin.H{
					"user":  user,
					"email": email,
				})
			})
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
