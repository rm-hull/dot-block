package middlewares

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	sloggin "github.com/samber/slog-gin"
)

type Authenticator func(c *gin.Context) bool

func RequireAnyAuth(auths ...Authenticator) gin.HandlerFunc {
	return func(c *gin.Context) {
		for _, auth := range auths {
			if auth(c) {
				c.Next()
				return
			}
		}

		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
	}
}

func APIKeyAuth(apiKeys map[string]string) Authenticator {
	return func(c *gin.Context) bool {
		if len(apiKeys) == 0 {
			return false
		}

		apiKey := strings.TrimSpace(c.GetHeader("X-API-Key"))
		if apiKey == "" {
			return false
		}

		for user, key := range apiKeys {
			if key == apiKey {
				c.Set("user", user)
				sloggin.AddCustomAttributes(c, slog.String("request.user-name", user))
				return true
			}
		}

		return false
	}
}

func ProxyAuth(devMode bool) Authenticator {
	return func(c *gin.Context) bool {
		if devMode {
			c.Set("user", "dev")
			c.Set("email", "dev@local.test")
			return true
		}

		user := c.GetHeader("X-Auth-Request-User")
		if user == "" {
			return false
		}

		c.Set("user", user)
		c.Set("email", c.GetHeader("X-Auth-Request-Email"))
		sloggin.AddCustomAttributes(c, slog.String("request.user-name", user))
		return true
	}
}
