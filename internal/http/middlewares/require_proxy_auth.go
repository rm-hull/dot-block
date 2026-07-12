package middlewares

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func RequireProxyAuth(devMode bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		if devMode {
			c.Set("user", "dev")
			c.Set("email", "dev@local.test")
			c.Next()
			return
		}

		user := c.GetHeader("X-Forwarded-User")
		if user == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing auth"})
			return
		}

		c.Set("user", user)
		c.Set("email", c.GetHeader("X-Forwarded-Email"))
		c.Next()
	}
}
