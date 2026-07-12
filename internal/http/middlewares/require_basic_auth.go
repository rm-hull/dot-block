package middlewares

import (
	"log/slog"
	"strings"

	"github.com/gin-gonic/gin"
)

func RequireBasicAuth(auth string, logger *slog.Logger) gin.HandlerFunc {
	if auth == "" {
		logger.Warn("Metrics endpoint is not protected by basic auth")
		return func(c *gin.Context) {
			c.Next()
		}
	}

	parts := strings.SplitN(auth, ":", 2)
	if len(parts) != 2 {
		panic("invalid basic auth value: " + auth)
	}
	user := parts[0]
	pass := parts[1]

	logger.Info("Protecting /metrics endpoint with basic auth")
	return gin.BasicAuth(gin.Accounts{user: pass})
}