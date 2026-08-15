package middlewares

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
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

		description, ok := apiKeys[apiKey]
		if !ok {
			return false
		}

		c.Set("user", description)
		return true
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
		return true
	}
}
