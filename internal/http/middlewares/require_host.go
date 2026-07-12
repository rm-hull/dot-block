package middlewares

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// RequireHost only allows the request through if it arrived on the expected
// hostname. Anything else gets a plain 404 — not 401/403 — so we don't even
// confirm to a prober that an admin surface exists behind the wrong host.
func RequireHost(expectedHost string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// c.Request.Host may include a port; strip it before comparing.
		host := c.Request.Host
		if i := strings.IndexByte(host, ':'); i != -1 {
			host = host[:i]
		}

		if !strings.EqualFold(host, expectedHost) {
			c.AbortWithStatus(http.StatusNotFound)
			return
		}
		c.Next()
	}
}
